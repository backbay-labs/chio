use chio_appraisal::{verify_runtime_attestation_record, VerifiedRuntimeAttestationRecord};
use chio_core::capability::runtime_attestation::RuntimeAttestationEvidence;
use chio_kernel::KernelError;

use crate::policy::RuntimeAssuranceIssuancePolicy;

fn validate_runtime_attestation_binding(
    runtime_attestation: Option<&RuntimeAttestationEvidence>,
) -> Result<(), KernelError> {
    if let Some(attestation) = runtime_attestation {
        attestation
            .validate_workload_identity_binding()
            .map_err(|error| {
                KernelError::CapabilityIssuanceDenied(format!(
                    "runtime attestation workload identity is invalid: {error}"
                ))
            })?;
    }
    Ok(())
}

pub(in crate::issuance) fn verify_runtime_attestation_for_issuance(
    runtime_attestation: Option<&RuntimeAttestationEvidence>,
    policy: Option<&RuntimeAssuranceIssuancePolicy>,
    now: u64,
) -> Result<Option<VerifiedRuntimeAttestationRecord>, KernelError> {
    let Some(runtime_attestation) = runtime_attestation else {
        return Ok(None);
    };
    let Some(policy) = policy else {
        validate_runtime_attestation_binding(Some(runtime_attestation))?;
        return verify_runtime_attestation_record(runtime_attestation, None, now)
            .map(Some)
            .map_err(|error| {
                KernelError::CapabilityIssuanceDenied(format!(
                    "runtime attestation evidence rejected by local verification boundary: {error}"
                ))
            });
    };

    verify_runtime_attestation_record(
        runtime_attestation,
        policy.attestation_trust_policy.as_ref(),
        now,
    )
    .map(Some)
    .map_err(|error| {
        KernelError::CapabilityIssuanceDenied(format!(
            "runtime attestation evidence rejected by local verification boundary: {error}"
        ))
    })
}
