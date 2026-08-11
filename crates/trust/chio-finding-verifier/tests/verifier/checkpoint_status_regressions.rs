use super::*;

#[test]
fn production_checkpoint_must_predate_the_finding() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    let checkpoint = evidence
        .checkpoints
        .first_mut()
        .ok_or("production checkpoint missing")?;
    checkpoint.body.issued_at = finding.issued_at.saturating_add(1);
    checkpoint.signature = keypair(21).sign(&canonical_json_bytes(&checkpoint.body)?);
    evidence.checkpoint_transparency =
        build_checkpoint_transparency(std::slice::from_ref(checkpoint))?;

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::CheckpointMembership),
        Some(FindingFacetOutcome::Failed)
    );
    Ok(())
}

#[test]
fn revoked_checkpoint_signer_cannot_backdate_new_evidence() -> TestResult {
    let fx = fixture()?;
    let mut trust = trust_roots(&fx);
    let status_trust = trust
        .checkpoint_signer_status
        .as_mut()
        .ok_or("checkpoint signer status trust missing")?;
    let signed_status = status_trust
        .signed_statuses
        .iter_mut()
        .find(|signed| signed.body == fx.checkpoint_signer_status.body)
        .ok_or("checkpoint signer status missing")?;
    signed_status.body.revoked_from = Some(signed_status.body.observed_at.saturating_sub(1));
    signed_status.signature = fx
        .checkpoint_status_authority
        .sign(&canonical_json_bytes(&signed_status.body)?);

    let draft =
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::CheckpointMembership),
        Some(FindingFacetOutcome::Failed)
    );
    Ok(())
}

#[test]
fn resolved_nonce_envelopes_change_the_bundle_commitment() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let original =
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;
    let mut changed_nonces = fx.nonce_resolver.nonces.clone();
    let changed = changed_nonces
        .first_mut()
        .ok_or("execution nonce evidence missing")?;
    changed.nonce.expires_at = changed.nonce.expires_at.saturating_add(1);
    changed.signature = keypair(21).sign(&canonical_json_bytes(&changed.nonce)?);
    let changed_resolver = TestNonceResolver {
        nonces: changed_nonces,
    };
    let mut changed_bundle = bundle(&fx, clone_receipts(&fx));
    changed_bundle.nonce_resolver = &changed_resolver;
    let changed = verify_finding_evidence(&fx.raw_finding, &trust, &changed_bundle)?;

    assert_eq!(
        changed.facet_outcome(FindingFacetKind::MeteredExposureBacking),
        Some(FindingFacetOutcome::Verified)
    );
    assert_ne!(
        original.resolved_evidence_bundle_sha256,
        changed.resolved_evidence_bundle_sha256
    );
    Ok(())
}
