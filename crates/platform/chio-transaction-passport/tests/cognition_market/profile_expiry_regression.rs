use super::*;

pub(super) fn finding_fixture_bytes() -> TestResult<Vec<u8>> {
    let finding: chio_finding::Finding = serde_json::from_slice(include_bytes!(
        "../../../../../fixtures/proof-room/finding/verified-fix-basic/finding.json"
    ))?;
    chio_finding::verify_finding(&finding)?;
    Ok(canonical_json_bytes(&finding)?)
}

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

#[test]
fn cognition_market_qualified_profile_rejects_backdated_report_after_finding_expiry() -> TestResult
{
    let finding: chio_finding::Finding = serde_json::from_slice(&finding_fixture_bytes()?)?;
    let mut bundle = build_bundle()?;
    replace_trusted_profile(&mut bundle, |profile| {
        profile.expires_at = finding.expires_at + 600;
        profile.verifier_report_signer.valid_until = finding.expires_at + 600;
    })?;
    let mut status = bundle
        .trust
        .verifier_authority_status
        .signed_status
        .body
        .clone();
    status.observed_at = finding.expires_at;
    bundle.trust.verifier_authority_status.signed_status =
        SignedExportEnvelope::sign(status, &Keypair::from_seed(&[10_u8; 32]))?;
    bundle.trust.verifier_authority_status.checked_at = finding.expires_at;

    let error = verify(&bundle)
        .err()
        .ok_or("backdated report under an expired Finding was accepted")?
        .to_string();
    assert!(
        error.contains("after Finding expiration"),
        "unexpected error: {error}"
    );
    Ok(())
}
