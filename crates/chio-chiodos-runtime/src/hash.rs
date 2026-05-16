use crate::error::ChiodosRuntimeError;
use crate::types::*;
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};
use serde::Serialize;

pub fn runtime_orchestration_profile_sha256(
    profile: &RuntimeOrchestrationProfile,
) -> Result<String, ChiodosRuntimeError> {
    canonical_sha256(profile)
}

pub fn runtime_run_contract_sha256(
    contract: &RuntimeRunContract,
) -> Result<String, ChiodosRuntimeError> {
    canonical_sha256(contract)
}

pub fn runtime_supervisor_profile_sha256(
    profile: &RuntimeSupervisorProfile,
) -> Result<String, ChiodosRuntimeError> {
    canonical_sha256(profile)
}

pub fn runtime_artifact_retention_profile_sha256(
    profile: &RuntimeArtifactRetentionProfile,
) -> Result<String, ChiodosRuntimeError> {
    canonical_sha256(profile)
}

pub fn buyer_attestation_packet_sha256(
    packet: &BuyerAttestationPacket,
) -> Result<String, ChiodosRuntimeError> {
    canonical_sha256(packet)
}

pub fn runtime_admission_bundle_sha256(
    bundle: &RuntimeAdmissionBundle,
) -> Result<String, ChiodosRuntimeError> {
    let bytes = canonical_json_bytes(bundle)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn runtime_verifier_trust_bundle_sha256(
    bundle: &RuntimeVerifierTrustBundleV4,
) -> Result<String, ChiodosRuntimeError> {
    let bytes = canonical_json_bytes(bundle)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn runtime_pheromone_policy_sha256(
    policy: &RuntimePheromonePolicy,
) -> Result<String, ChiodosRuntimeError> {
    let bytes = canonical_json_bytes(policy)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn runtime_peer_weights_sha256(
    weights: &RuntimePeerWeights,
) -> Result<String, ChiodosRuntimeError> {
    let bytes = canonical_json_bytes(weights)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn tool_args_sha256(arguments: &serde_json::Value) -> Result<String, ChiodosRuntimeError> {
    let bytes = canonical_json_bytes(arguments)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub(crate) fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, ChiodosRuntimeError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}
