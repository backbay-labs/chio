use super::*;

#[test]
fn cognition_market_qualified_profile_rejects_backdated_report_after_profile_expiry() -> TestResult
{
    let mut bundle = build_bundle()?;
    replace_trusted_profile(&mut bundle, |profile| {
        profile.expires_at = CHECKED_AT + 1;
    })?;
    let mut status = bundle
        .trust
        .verifier_authority_status
        .signed_status
        .body
        .clone();
    status.observed_at = CHECKED_AT + 2;
    bundle.trust.verifier_authority_status.signed_status =
        SignedExportEnvelope::sign(status, &Keypair::from_seed(&[10_u8; 32]))?;
    bundle.trust.verifier_authority_status.checked_at = CHECKED_AT + 2;

    let error = verify(&bundle)
        .err()
        .ok_or("backdated report under an expired verifier profile was accepted")?
        .to_string();
    assert!(
        error.contains("after verifier-profile expiration"),
        "unexpected error: {error}"
    );
    Ok(())
}
