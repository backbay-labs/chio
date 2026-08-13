use super::*;

#[test]
fn cognition_market_qualified_profile_rejects_self_pinned_governance() -> TestResult {
    let mut bundle = build_bundle()?;
    let unauthorized_governance = Keypair::from_seed(&[88_u8; 32]);
    let mut profile = bundle.trust.trusted_verifier_profile.body.clone();
    profile.governance_authority = unauthorized_governance.public_key();
    profile.required_facets.clear();
    profile.profile_id = compute_profile_id(&profile)?;
    let signed = SignedExportEnvelope::sign(profile, &unauthorized_governance)?;
    bundle.trust.trusted_verifier_profile_envelope_sha256 = signed_envelope_sha256(&signed)?;
    bundle.trust.trusted_verifier_profile = signed;

    let error = verify(&bundle)
        .err()
        .ok_or("a self-pinned profile governance authority was accepted")?
        .to_string();
    assert!(
        error.contains("governance key does not match the deployment-pinned policy"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_rejects_aliased_authorities() -> TestResult {
    let mut bundle = build_bundle()?;
    bundle.trust.finding_verifier_authority = bundle.trust.profile_governance_authority.key.clone();

    let error = verify(&bundle)
        .err()
        .ok_or("aliased governance and verifier authorities were accepted")?
        .to_string();
    assert!(
        error.contains("governance and finding verifier authorities must be distinct"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_rejects_verifier_as_governance_status_authority() -> TestResult
{
    let mut bundle = build_bundle()?;
    bundle
        .trust
        .profile_governance_authority_status
        .status_authority
        .key = bundle.trust.finding_verifier_authority.clone();

    let error = verify(&bundle)
        .err()
        .ok_or("finding verifier was accepted as the governance-status authority")?
        .to_string();
    assert!(
        error.contains(
            "profile-governance status authority and finding verifier authority must be distinct"
        ),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_rejects_backdated_profile_after_governance_revocation(
) -> TestResult {
    let mut bundle = build_bundle()?;
    let mut status = bundle
        .trust
        .profile_governance_authority_status
        .signed_status
        .body
        .clone();
    status.revoked_from = Some(CHECKED_AT);
    bundle
        .trust
        .profile_governance_authority_status
        .signed_status = SignedExportEnvelope::sign(status, &Keypair::from_seed(&[10_u8; 32]))?;

    let error = verify(&bundle)
        .err()
        .ok_or("profile signed by a revoked governance key was accepted")?
        .to_string();
    assert!(
        error.contains("after profile-governance key revocation"),
        "unexpected error: {error}"
    );
    Ok(())
}
