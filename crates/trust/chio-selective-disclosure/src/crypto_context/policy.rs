use crate::{SelectiveDisclosureProof, BBS_CIPHERSUITE_SHA256};

use super::types::{
    CryptoVerificationContext, DisclosureContextCheck, DisclosureCryptoContextError,
    DisclosureVerifierPrivacyProfile, HolderBindingStatus, KeyStateStatus, NonceReplayStatus,
    RevocationSnapshotStatus, CRYPTO_VERIFICATION_CONTEXT_SCHEMA_V1,
    DISCLOSURE_VERIFIER_PRIVACY_PROFILE_SCHEMA_V1, TRUST_KEY_STATE_SCHEMA_V1,
    TRUST_REVOCATION_SNAPSHOT_SCHEMA_V1,
};

const MECHANISM_BBS: &str = "bbs";

pub(super) fn validate_context_shape(
    context: &CryptoVerificationContext,
    profile: &DisclosureVerifierPrivacyProfile,
) -> Result<(), DisclosureCryptoContextError> {
    require_schema(
        &context.schema,
        CRYPTO_VERIFICATION_CONTEXT_SCHEMA_V1,
        "context.schema",
    )?;
    require_schema(
        &context.key_state.schema,
        TRUST_KEY_STATE_SCHEMA_V1,
        "key_state.schema",
    )?;
    if let Some(snapshot) = &context.revocation_snapshot {
        require_schema(
            &snapshot.schema,
            TRUST_REVOCATION_SNAPSHOT_SCHEMA_V1,
            "revocation_snapshot.schema",
        )?;
    }
    require_schema(
        &profile.schema,
        DISCLOSURE_VERIFIER_PRIVACY_PROFILE_SCHEMA_V1,
        "profile.schema",
    )?;

    for (field, value) in [
        ("context_id", context.context_id.as_str()),
        ("artifact_ref", context.artifact_ref.as_str()),
        ("proof_mechanism", context.proof_mechanism.as_str()),
        ("issuer", context.issuer.as_str()),
        ("issuer_key_ref", context.issuer_key_ref.as_str()),
        ("algorithm", context.algorithm.as_str()),
        ("suite", context.suite.as_str()),
        ("hash_algorithm", context.hash_algorithm.as_str()),
        ("canonicalization", context.canonicalization.as_str()),
        ("signature_ref", context.signature_ref.as_str()),
        ("audience", context.audience.as_str()),
        ("nonce_hex", context.nonce_hex.as_str()),
        ("profile_id", profile.profile_id.as_str()),
        ("required_audience", profile.required_audience.as_str()),
        ("nonce_policy", profile.nonce_policy.as_str()),
    ] {
        require_non_empty(value, field)?;
    }
    validate_hex(&context.nonce_hex, "nonce_hex")?;
    Ok(())
}

pub(super) fn collect_context_checks(
    proof: &SelectiveDisclosureProof,
    context: &CryptoVerificationContext,
    profile: &DisclosureVerifierPrivacyProfile,
) -> Vec<DisclosureContextCheck> {
    let mut checks = Vec::new();
    collect_proof_binding_checks(proof, context, profile, &mut checks);
    collect_key_state_checks(context, profile, &mut checks);
    collect_revocation_checks(context, profile, &mut checks);
    collect_presentation_context_checks(proof, context, profile, &mut checks);
    checks
}

fn collect_proof_binding_checks(
    proof: &SelectiveDisclosureProof,
    context: &CryptoVerificationContext,
    profile: &DisclosureVerifierPrivacyProfile,
    checks: &mut Vec<DisclosureContextCheck>,
) {
    if context.artifact_ref != proof.subject_sha256_hex {
        checks.push(DisclosureContextCheck::new(
            "disclosure_context_artifact_mismatch",
            "crypto context artifact_ref did not match selective disclosure proof subject",
        ));
    }
    if context.proof_mechanism != MECHANISM_BBS
        || !profile
            .allowed_proof_mechanisms
            .iter()
            .any(|item| item == MECHANISM_BBS)
    {
        checks.push(DisclosureContextCheck::new(
            "disclosure_context_proof_mechanism_not_allowed",
            "privacy profile did not allow the BBS proof mechanism",
        ));
    }
    if context.issuer_key_ref != proof.issuer_fingerprint
        || context.key_state.key_ref != proof.issuer_fingerprint
    {
        checks.push(DisclosureContextCheck::new(
            "disclosure_context_issuer_key_mismatch",
            "crypto context key refs did not match proof issuer fingerprint",
        ));
    }
    if !profile
        .allowed_issuer_keys
        .iter()
        .any(|item| item == &proof.issuer_fingerprint)
    {
        checks.push(DisclosureContextCheck::new(
            "disclosure_context_issuer_key_not_allowed",
            "privacy profile did not allow the proof issuer key",
        ));
    }
    if context.suite != proof.ciphersuite || context.suite != BBS_CIPHERSUITE_SHA256 {
        checks.push(DisclosureContextCheck::new(
            "disclosure_context_suite_mismatch",
            "crypto context suite did not match the verified BBS proof suite",
        ));
    }
    if profile
        .forbidden_algorithms
        .iter()
        .any(|item| item == &context.algorithm)
    {
        checks.push(DisclosureContextCheck::new(
            "disclosure_context_algorithm_forbidden",
            "privacy profile explicitly forbids the context algorithm",
        ));
    } else if !profile
        .allowed_algorithms
        .iter()
        .any(|item| item == &context.algorithm)
    {
        checks.push(DisclosureContextCheck::new(
            "disclosure_context_algorithm_not_allowed",
            "privacy profile did not allow the context algorithm",
        ));
    }
}

fn collect_key_state_checks(
    context: &CryptoVerificationContext,
    profile: &DisclosureVerifierPrivacyProfile,
    checks: &mut Vec<DisclosureContextCheck>,
) {
    if context.key_state.status != KeyStateStatus::Active {
        checks.push(DisclosureContextCheck::new(
            "disclosure_context_key_not_active",
            "issuer key state was not active at verification time",
        ));
    }
    if context.verification_time < context.key_state.valid_from
        || context.verification_time > context.key_state.valid_until
    {
        checks.push(DisclosureContextCheck::new(
            "disclosure_context_key_not_active",
            "verification time was outside the issuer key validity window",
        ));
    }
    if context.key_state.epoch < profile.required_key_epoch_min {
        checks.push(DisclosureContextCheck::new(
            "disclosure_context_key_epoch_too_old",
            "issuer key epoch was older than the privacy profile minimum",
        ));
    }
    if profile
        .forbidden_key_epochs
        .contains(&context.key_state.epoch)
    {
        checks.push(DisclosureContextCheck::new(
            "disclosure_context_key_epoch_forbidden",
            "issuer key epoch was forbidden by the privacy profile",
        ));
    }
}

fn collect_revocation_checks(
    context: &CryptoVerificationContext,
    profile: &DisclosureVerifierPrivacyProfile,
    checks: &mut Vec<DisclosureContextCheck>,
) {
    let Some(snapshot) = context.revocation_snapshot.as_ref() else {
        checks.push(DisclosureContextCheck::new(
            "disclosure_context_revocation_snapshot_missing",
            "privacy profile required a fresh revocation snapshot",
        ));
        return;
    };

    if snapshot.status != RevocationSnapshotStatus::Fresh {
        checks.push(DisclosureContextCheck::new(
            "disclosure_context_revocation_snapshot_invalid",
            "revocation snapshot was not fresh",
        ));
    }
    if context.verification_time < snapshot.issued_at
        || context.verification_time > snapshot.expires_at
    {
        checks.push(DisclosureContextCheck::new(
            "disclosure_context_revocation_snapshot_invalid",
            "verification time was outside the revocation snapshot window",
        ));
    }
    let age = context.verification_time.saturating_sub(snapshot.issued_at);
    if age > profile.required_status_freshness_seconds {
        checks.push(DisclosureContextCheck::new(
            "disclosure_context_revocation_snapshot_stale",
            "revocation snapshot exceeded the profile freshness window",
        ));
    }
}

fn collect_presentation_context_checks(
    proof: &SelectiveDisclosureProof,
    context: &CryptoVerificationContext,
    profile: &DisclosureVerifierPrivacyProfile,
    checks: &mut Vec<DisclosureContextCheck>,
) {
    if context.audience != profile.required_audience {
        checks.push(DisclosureContextCheck::new(
            "disclosure_context_audience_mismatch",
            "presentation audience did not match the verifier privacy profile",
        ));
    }
    if context.nonce_hex != proof.proof_nonce_hex {
        checks.push(DisclosureContextCheck::new(
            "disclosure_context_nonce_mismatch",
            "crypto context nonce did not match the verified proof nonce",
        ));
    }
    if profile.nonce_policy == "no_replay"
        && context.nonce_replay_status != NonceReplayStatus::Fresh
    {
        checks.push(DisclosureContextCheck::new(
            "disclosure_context_nonce_replayed",
            "nonce was not fresh under a no-replay privacy profile",
        ));
    }
    if let Some(required_holder) = &profile.required_holder_binding {
        if context.holder_binding_ref.as_ref() != Some(required_holder)
            || context.holder_binding_status != HolderBindingStatus::Bound
        {
            checks.push(DisclosureContextCheck::new(
                "disclosure_context_holder_binding_missing",
                "required holder binding was missing or not bound",
            ));
        }
    }
    if context.transparency_state < profile.required_transparency_state {
        checks.push(DisclosureContextCheck::new(
            "disclosure_context_transparency_state_insufficient",
            "context transparency state was weaker than the profile requirement",
        ));
    }
    if context.presentation_created_at > context.verification_time {
        checks.push(DisclosureContextCheck::new(
            "disclosure_context_presentation_time_invalid",
            "presentation was created after verification time",
        ));
    } else {
        let age = context
            .verification_time
            .saturating_sub(context.presentation_created_at);
        if age > profile.max_presentation_age_seconds {
            checks.push(DisclosureContextCheck::new(
                "disclosure_context_presentation_stale",
                "presentation age exceeded the profile maximum",
            ));
        }
    }
}

fn require_schema(
    actual: &str,
    expected: &'static str,
    field: &'static str,
) -> Result<(), DisclosureCryptoContextError> {
    if actual == expected {
        Ok(())
    } else {
        Err(DisclosureCryptoContextError::InvalidContext(format!(
            "{field} expected {expected}, got {actual}"
        )))
    }
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), DisclosureCryptoContextError> {
    if value.trim().is_empty() {
        Err(DisclosureCryptoContextError::InvalidContext(format!(
            "{field} must not be empty"
        )))
    } else {
        Ok(())
    }
}

fn validate_hex(value: &str, field: &'static str) -> Result<(), DisclosureCryptoContextError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DisclosureCryptoContextError::InvalidContext(format!(
            "{field} must be lowercase hex"
        )));
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(DisclosureCryptoContextError::InvalidContext(format!(
            "{field} must use lowercase hex"
        )));
    }
    Ok(())
}
