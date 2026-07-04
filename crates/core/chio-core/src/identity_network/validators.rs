use std::collections::HashSet;

use url::Url;

use super::error::IdentityNetworkContractError;
use super::types::{
    IdentityArtifactReference, IdentityBindingPolicy, IdentityDidMethod,
    WalletDirectoryLookupGuardrails, WalletRoutingGuardrails, WalletTransportMode,
};

pub(super) fn validate_identity_artifact_reference(
    reference: &IdentityArtifactReference,
) -> Result<(), IdentityNetworkContractError> {
    ensure_non_empty(&reference.schema, "reference.schema")?;
    ensure_non_empty(&reference.artifact_id, "reference.artifact_id")?;
    ensure_non_empty(&reference.operator_id, "reference.operator_id")?;
    validate_hex_digest(&reference.sha256, "reference.sha256")?;
    if let Some(uri) = reference.uri.as_ref() {
        validate_https_url(uri, "reference.uri")?;
    }
    Ok(())
}

pub(super) fn validate_identity_binding_policy(
    policy: &IdentityBindingPolicy,
) -> Result<(), IdentityNetworkContractError> {
    if !policy.requires_chio_subject_provenance {
        return Err(IdentityNetworkContractError::InvalidProfile(
            "public identity profiles must require Chio subject provenance".to_string(),
        ));
    }
    if !policy.requires_chio_issuer_provenance {
        return Err(IdentityNetworkContractError::InvalidProfile(
            "public identity profiles must require Chio issuer provenance".to_string(),
        ));
    }
    if !policy.requires_same_subject_across_credentials {
        return Err(IdentityNetworkContractError::InvalidProfile(
            "public identity profiles must require the same subject across credentials".to_string(),
        ));
    }
    if !policy.manual_subject_rebinding_required {
        return Err(IdentityNetworkContractError::InvalidProfile(
            "public identity profiles must require manual subject rebinding review".to_string(),
        ));
    }
    if !policy.unsupported_mappings_fail_closed {
        return Err(IdentityNetworkContractError::InvalidProfile(
            "public identity profiles must fail closed on unsupported mappings".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_wallet_directory_lookup_guardrails(
    guardrails: &WalletDirectoryLookupGuardrails,
) -> Result<(), IdentityNetworkContractError> {
    if !guardrails.requires_explicit_verifier_binding {
        return Err(IdentityNetworkContractError::InvalidDirectoryEntry(
            "wallet directory entries must require explicit verifier binding".to_string(),
        ));
    }
    if !guardrails.requires_manual_subject_binding_review {
        return Err(IdentityNetworkContractError::InvalidDirectoryEntry(
            "wallet directory entries must require manual subject binding review".to_string(),
        ));
    }
    if !guardrails.reject_ambient_directory_trust {
        return Err(IdentityNetworkContractError::InvalidDirectoryEntry(
            "wallet directory entries must reject ambient directory trust".to_string(),
        ));
    }
    if !guardrails.fail_closed_on_unknown_wallet_family {
        return Err(IdentityNetworkContractError::InvalidDirectoryEntry(
            "wallet directory entries must fail closed on unknown wallet families".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_wallet_routing_guardrails(
    guardrails: &WalletRoutingGuardrails,
) -> Result<(), IdentityNetworkContractError> {
    if !guardrails.requires_explicit_verifier_binding {
        return Err(IdentityNetworkContractError::InvalidRouting(
            "wallet routing manifests must require explicit verifier binding".to_string(),
        ));
    }
    if !guardrails.requires_replay_safe_exchange {
        return Err(IdentityNetworkContractError::InvalidRouting(
            "wallet routing manifests must require replay-safe exchange".to_string(),
        ));
    }
    if !guardrails.fail_closed_on_subject_mismatch {
        return Err(IdentityNetworkContractError::InvalidRouting(
            "wallet routing manifests must fail closed on subject mismatch".to_string(),
        ));
    }
    if !guardrails.fail_closed_on_cross_operator_issuer_mismatch {
        return Err(IdentityNetworkContractError::InvalidRouting(
            "wallet routing manifests must fail closed on cross-operator issuer mismatch"
                .to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_https_url(
    value: &str,
    field: &'static str,
) -> Result<(), IdentityNetworkContractError> {
    ensure_non_empty(value, field)?;
    let parsed = Url::parse(value).map_err(|error| {
        IdentityNetworkContractError::InvalidReference(format!("{field}: {error}"))
    })?;
    if parsed.scheme() != "https" {
        return Err(IdentityNetworkContractError::InvalidReference(format!(
            "{field}: expected https URL"
        )));
    }
    Ok(())
}

pub(super) fn validate_hex_digest(
    value: &str,
    field: &'static str,
) -> Result<(), IdentityNetworkContractError> {
    if value.len() != 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(IdentityNetworkContractError::InvalidReference(format!(
            "{field}: expected 64 hex characters"
        )));
    }
    Ok(())
}

pub(super) fn contains_non_chio_method(methods: &[IdentityDidMethod]) -> bool {
    methods
        .iter()
        .any(|method| *method != IdentityDidMethod::DidChio)
}

pub(super) fn ensure_required_transports(
    transports: &[WalletTransportMode],
    field: &'static str,
) -> Result<(), IdentityNetworkContractError> {
    ensure_unique_copy_values(transports, field)?;
    let transport_set: HashSet<_> = transports.iter().copied().collect();
    let required = HashSet::from([
        WalletTransportMode::Oid4vpSameDevice,
        WalletTransportMode::Oid4vpCrossDevice,
        WalletTransportMode::Oid4vpRelay,
    ]);
    if transport_set != required {
        return Err(IdentityNetworkContractError::DuplicateValue(format!(
            "{field}:must include same-device, cross-device, and relay"
        )));
    }
    Ok(())
}

pub(super) fn ensure_refs_present(
    references: &[IdentityArtifactReference],
    field: &'static str,
) -> Result<(), IdentityNetworkContractError> {
    if references.is_empty() {
        return Err(IdentityNetworkContractError::MissingField(field));
    }
    let composite_ids = references
        .iter()
        .map(|reference| format!("{}:{}", reference.operator_id, reference.artifact_id))
        .collect::<Vec<_>>();
    ensure_unique_strings(&composite_ids, field)?;
    Ok(())
}

pub(super) fn ensure_non_empty(
    value: &str,
    field: &'static str,
) -> Result<(), IdentityNetworkContractError> {
    if value.trim().is_empty() {
        return Err(IdentityNetworkContractError::MissingField(field));
    }
    Ok(())
}

pub(super) fn ensure_unique_strings(
    values: &[String],
    field: &'static str,
) -> Result<(), IdentityNetworkContractError> {
    let mut seen = HashSet::new();
    for value in values {
        if value.trim().is_empty() {
            return Err(IdentityNetworkContractError::MissingField(field));
        }
        if !seen.insert(value.as_str()) {
            return Err(IdentityNetworkContractError::DuplicateValue(format!(
                "{field}:{value}"
            )));
        }
    }
    Ok(())
}

pub(super) fn ensure_unique_copy_values<T>(
    values: &[T],
    field: &'static str,
) -> Result<(), IdentityNetworkContractError>
where
    T: Copy + Eq + std::hash::Hash + std::fmt::Debug,
{
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(*value) {
            return Err(IdentityNetworkContractError::DuplicateValue(format!(
                "{field}:{value:?}"
            )));
        }
    }
    Ok(())
}
