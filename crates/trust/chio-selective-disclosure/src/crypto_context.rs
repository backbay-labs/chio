#[cfg(feature = "bbs")]
mod policy;
mod types;

pub use types::{
    CryptoVerificationContext, DisclosureContextCheck, DisclosureContextVerdict,
    DisclosureCryptoContextError, DisclosureCryptoContextReport, DisclosureKeyState,
    DisclosureRevocationSnapshot, DisclosureVerifierPrivacyProfile, HolderBindingStatus,
    KeyStateStatus, NonceReplayStatus, RevocationSnapshotStatus, TransparencyState,
    CRYPTO_VERIFICATION_CONTEXT_SCHEMA_V1, DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1,
    DISCLOSURE_VERIFIER_PRIVACY_PROFILE_SCHEMA_V1, TRUST_KEY_STATE_SCHEMA_V1,
    TRUST_REVOCATION_SNAPSHOT_SCHEMA_V1,
};

#[cfg(feature = "bbs")]
use crate::{verify_selective_disclosure_proof, InMemoryIssuerRegistry, SelectiveDisclosureProof};
#[cfg(feature = "bbs")]
use policy::collect_context_checks;

#[cfg(feature = "bbs")]
const CLAIM_DISCLOSURE_CRYPTO_CONTEXT_BOUND: &str = "claim.disclosure.crypto_context_bound";
#[cfg(feature = "bbs")]
const CLAIM_DISCLOSURE_PROFILE_CONTEXT_POLICY_ENFORCED: &str =
    "claim.disclosure.profile_context_policy_enforced";

#[cfg(feature = "bbs")]
pub fn verify_selective_disclosure_with_context(
    proof: &SelectiveDisclosureProof,
    registry: &InMemoryIssuerRegistry,
    context: &CryptoVerificationContext,
    profile: &DisclosureVerifierPrivacyProfile,
) -> Result<DisclosureCryptoContextReport, DisclosureCryptoContextError> {
    let verified = verify_selective_disclosure_proof(proof, registry)?;
    policy::validate_context_shape(context, profile)?;

    let rejected_checks = collect_context_checks(proof, context, profile);
    let verdict = if rejected_checks.is_empty() {
        DisclosureContextVerdict::Verified
    } else {
        DisclosureContextVerdict::Rejected
    };
    let verified_claims = if verdict == DisclosureContextVerdict::Verified {
        vec![
            CLAIM_DISCLOSURE_CRYPTO_CONTEXT_BOUND.to_string(),
            CLAIM_DISCLOSURE_PROFILE_CONTEXT_POLICY_ENFORCED.to_string(),
        ]
    } else {
        Vec::new()
    };

    Ok(DisclosureCryptoContextReport {
        schema: DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1.to_string(),
        id: format!("disclosure-crypto-context-report-{}", context.context_id),
        context_id: context.context_id.clone(),
        artifact_ref: context.artifact_ref.clone(),
        projection_manifest_ref: proof.projection_version.clone(),
        verdict,
        evidence_class: "verifier_context".to_string(),
        cryptographic_proof_verified: true,
        verified_claims,
        rejected_checks,
        disclosed_fields: verified
            .disclosed
            .iter()
            .map(|message| message.field.clone())
            .collect(),
        signature: None,
    })
}
