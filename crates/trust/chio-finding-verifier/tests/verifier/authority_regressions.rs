use super::*;

#[test]
fn backing_accepted_at_or_after_evaluation_is_not_verified() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let mut evidence_bundle = bundle(&fx, clone_receipts(&fx));
    let snapshot = evidence_bundle
        .bond_snapshot
        .as_mut()
        .ok_or("bond snapshot missing")?;
    snapshot.store_snapshot.body.accepted_at = trust.trusted_time;
    snapshot.store_snapshot =
        SignedExportEnvelope::sign(snapshot.store_snapshot.body.clone(), &keypair(4))?;
    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence_bundle)?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::BondBacking),
        Some(FindingFacetOutcome::Failed)
    );
    assert!(draft.backing_allocation_id.is_none());
    assert!(!draft.satisfies_required_facets(&fx.profile.body));
    Ok(())
}

#[test]
fn backing_cannot_be_accepted_before_its_signed_issue_time() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let mut evidence_bundle = bundle(&fx, clone_receipts(&fx));
    let snapshot = evidence_bundle
        .bond_snapshot
        .as_mut()
        .ok_or("bond snapshot missing")?;
    let mut backing = snapshot.backing.body.clone();
    backing.issued_at = snapshot.store_snapshot.body.accepted_at.saturating_add(1);
    backing.allocation_id = compute_allocation_id(&backing)?;
    snapshot.backing = SignedExportEnvelope::sign(backing, &keypair(4))?;
    snapshot.store_snapshot.body.allocation_id = snapshot.backing.body.allocation_id.clone();
    snapshot.store_snapshot.body.backing_envelope_sha256 =
        sha256_hex(&canonical_json_bytes(&snapshot.backing)?);
    snapshot.store_snapshot =
        SignedExportEnvelope::sign(snapshot.store_snapshot.body.clone(), &keypair(4))?;

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence_bundle)?;
    let backing = draft
        .facets
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::BondBacking)
        .ok_or("bond-backing facet missing")?;
    assert_eq!(backing.outcome, FindingFacetOutcome::Failed);
    assert!(backing.reason.contains("before its signed issue time"));
    assert!(draft.backing_allocation_id.is_none());
    Ok(())
}

#[test]
fn bond_backing_must_bind_the_evaluated_verifier_profile() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let mut evidence_bundle = bundle(&fx, clone_receipts(&fx));
    let snapshot = evidence_bundle
        .bond_snapshot
        .as_mut()
        .ok_or("bond snapshot missing")?;
    let mut backing = snapshot.backing.body.clone();
    backing.profile_envelope_sha256 = "ab".repeat(32);
    backing.allocation_id = compute_allocation_id(&backing)?;
    snapshot.backing = SignedExportEnvelope::sign(backing, &keypair(4))?;
    snapshot.store_snapshot.body.allocation_id = snapshot.backing.body.allocation_id.clone();
    snapshot.store_snapshot.body.backing_envelope_sha256 =
        sha256_hex(&canonical_json_bytes(&snapshot.backing)?);
    snapshot.store_snapshot =
        SignedExportEnvelope::sign(snapshot.store_snapshot.body.clone(), &keypair(4))?;

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence_bundle)?;
    let backing = draft
        .facets
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::BondBacking)
        .ok_or("bond-backing facet missing")?;
    assert_eq!(backing.outcome, FindingFacetOutcome::Failed);
    assert!(
        backing.reason.contains("evaluated verifier profile"),
        "unexpected reason: {}",
        backing.reason
    );
    assert!(draft.backing_allocation_id.is_none());
    Ok(())
}

#[test]
fn unpinned_profile_or_empty_kernel_keys_reject_outright() -> TestResult {
    let fx = fixture()?;

    let mut trust = trust_roots(&fx);
    trust.governance_authority = keypair(9).public_key();
    assert_eq!(
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx))).err(),
        Some(FindingVerifierError::ProfileInvalid)
    );

    let mut trust = trust_roots(&fx);
    trust.admitted_kernel_keys.clear();
    assert_eq!(
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx))).err(),
        Some(FindingVerifierError::NoAdmittedKernelKeys)
    );
    Ok(())
}

#[test]
fn unsupported_profile_requirements_reject_outright() -> TestResult {
    let fx = fixture()?;

    for facet in [
        FindingFacetKind::KernelAndRevocationTrust,
        FindingFacetKind::IssuerLineage,
        FindingFacetKind::IntentBinding,
    ] {
        let mut profile = fx.profile.body.clone();
        profile.required_facets.push(facet);
        profile.profile_id = compute_profile_id(&profile)?;
        let mut trust = trust_roots(&fx);
        trust.profile = SignedExportEnvelope::sign(profile, &fx.governance)?;
        assert_eq!(
            verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))
                .err(),
            Some(FindingVerifierError::ProfileInvalid)
        );
    }

    let mut profile = fx.profile.body.clone();
    profile.required_receipt_semantics = "chio.unknown_spend.v1".to_owned();
    profile.profile_id = compute_profile_id(&profile)?;
    let mut trust = trust_roots(&fx);
    trust.profile = SignedExportEnvelope::sign(profile, &fx.governance)?;
    assert_eq!(
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx))).err(),
        Some(FindingVerifierError::ProfileInvalid)
    );

    let mut profile = fx.profile.body.clone();
    profile.predicate_engine = "foreign-replay-v1".to_owned();
    profile.profile_id = compute_profile_id(&profile)?;
    let mut trust = trust_roots(&fx);
    trust.profile = SignedExportEnvelope::sign(profile, &fx.governance)?;
    assert_eq!(
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx))).err(),
        Some(FindingVerifierError::ProfileInvalid)
    );
    Ok(())
}

#[test]
fn report_signing_requires_the_profile_authorized_key() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let draft =
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;
    let interloper = keypair(9);
    assert_eq!(
        sign_finding_verifier_report(&draft, &trust, "chio-finding-verifier/0.1", &interloper)
            .err(),
        Some(FindingVerifierError::ReportSignerMismatch)
    );
    // The issuer key is also not the report signer.
    assert!(
        sign_finding_verifier_report(&draft, &trust, "chio-finding-verifier/0.1", &fx.issuer)
            .is_err()
    );
    Ok(())
}

#[test]
fn receipt_and_checkpoint_signers_must_cover_the_evidence_timestamp() -> TestResult {
    let fx = fixture()?;

    let mut trust = trust_roots(&fx);
    let mut profile = fx.profile.body.clone();
    let first_receipt_time = fx.receipts[0].receipt.timestamp;
    for signer in &mut profile.receipt_signers {
        if signer.role == FindingReceiptRole::Production {
            signer.policy.valid_until = first_receipt_time;
        }
    }
    trust.profile = resign_profile(profile)?;
    let draft =
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::ReceiptAuthenticity),
        Some(FindingFacetOutcome::Failed)
    );

    let mut trust = trust_roots(&fx);
    let mut profile = fx.profile.body.clone();
    profile.checkpoint_logs[0].signer.valid_until = fx.checkpoint.body.issued_at;
    trust.profile = resign_profile(profile)?;
    let draft =
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::CheckpointMembership),
        Some(FindingFacetOutcome::Failed)
    );
    Ok(())
}

#[test]
fn report_signer_policy_must_cover_the_evaluation_time() -> TestResult {
    let fx = fixture()?;
    let mut trust = trust_roots(&fx);
    let mut profile = fx.profile.body.clone();
    profile.verifier_report_signer.valid_until = trust.trusted_time;
    trust.profile = resign_profile(profile)?;
    let draft =
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;
    assert_eq!(
        sign_finding_verifier_report(&draft, &trust, "chio-finding-verifier/0.1", &fx.verifier,)
            .err(),
        Some(FindingVerifierError::ReportSignerInactive)
    );
    Ok(())
}

#[test]
fn report_signing_rejects_profile_substitution_even_with_the_same_signer() -> TestResult {
    let fx = fixture()?;
    let original_trust = trust_roots(&fx);
    let draft = verify_finding_evidence(
        &fx.raw_finding,
        &original_trust,
        &bundle(&fx, clone_receipts(&fx)),
    )?;

    let mut substituted_trust = trust_roots(&fx);
    let mut substituted_profile = fx.profile.body.clone();
    substituted_profile.retention_policy_ref = "retention-seven-days-v1".to_string();
    substituted_trust.profile = resign_profile(substituted_profile)?;
    assert_eq!(
        substituted_trust.profile.body.verifier_report_signer,
        fx.profile.body.verifier_report_signer
    );
    assert_eq!(
        sign_finding_verifier_report(
            &draft,
            &substituted_trust,
            "chio-finding-verifier/0.1",
            &fx.verifier,
        )
        .err(),
        Some(FindingVerifierError::ReportProfileMismatch)
    );
    Ok(())
}

#[test]
fn report_signing_copies_the_trust_commitments_used_for_evaluation() -> TestResult {
    let fx = fixture()?;
    let mut evaluated_trust = trust_roots(&fx);
    evaluated_trust.trust_root_snapshot_sha256 = "1".repeat(64);
    evaluated_trust.resolver_policy_sha256 = "2".repeat(64);
    evaluated_trust.trusted_time_input_sha256 = "3".repeat(64);
    let draft = verify_finding_evidence(
        &fx.raw_finding,
        &evaluated_trust,
        &bundle(&fx, clone_receipts(&fx)),
    )?;

    let mut signing_trust = trust_roots(&fx);
    signing_trust.collateral_authority = keypair(44).public_key();
    signing_trust.trust_root_snapshot_sha256 = "4".repeat(64);
    signing_trust.resolver_policy_sha256 = "5".repeat(64);
    signing_trust.trusted_time_input_sha256 = "6".repeat(64);
    let report = sign_finding_verifier_report(
        &draft,
        &signing_trust,
        "chio-finding-verifier/0.1",
        &fx.verifier,
    )?;

    assert_eq!(report.body.trust_root_snapshot_sha256, "1".repeat(64));
    assert_eq!(report.body.resolver_policy_sha256, "2".repeat(64));
    assert_eq!(report.body.trusted_time_input_sha256, "3".repeat(64));
    Ok(())
}

#[test]
fn recipe_must_bind_the_finding_it_is_committed_by() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let profile_sha256 = sha256_hex(&canonical_json_bytes(&fx.profile)?);

    // A recipe for a different payload, committed at the right digest,
    // still fails: the digest proves retention, not aboutness.
    let other_payload = "1".repeat(64);
    let foreign = recipe(HEX64, &other_payload, &profile_sha256, HEX64);
    let foreign_bytes = canonical_json_bytes(&foreign)?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.recipe_preimage = Some(foreign_bytes.as_slice());
    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::RecipeBinding),
        Some(FindingFacetOutcome::Failed)
    );

    // A recipe committing an unadmitted profile fails the same way.
    let wrong_profile = recipe(HEX64, &fx.finding_payload_sha256, HEX64, HEX64);
    let wrong_bytes = canonical_json_bytes(&wrong_profile)?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.recipe_preimage = Some(wrong_bytes.as_slice());
    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::RecipeBinding),
        Some(FindingFacetOutcome::Failed)
    );
    Ok(())
}

#[test]
fn backing_signed_by_an_unpinned_authority_is_not_bond_evidence() -> TestResult {
    let fx = fixture()?;
    let mut trust = trust_roots(&fx);
    trust.collateral_authority = keypair(9).public_key();
    let draft =
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::BondBacking),
        Some(FindingFacetOutcome::Failed)
    );
    assert!(draft.backing_allocation_id.is_none());
    assert!(!draft.satisfies_required_facets(&fx.profile.body));
    Ok(())
}

#[test]
fn receipts_signed_by_an_unpinned_kernel_are_not_authentic() -> TestResult {
    let fx = fixture()?;
    let mut trust = trust_roots(&fx);
    // Drop the production signer pin while leaving the receipts and
    // their strict signatures untouched.
    let mut profile_body = fx.profile.body.clone();
    for signer in &mut profile_body.receipt_signers {
        if signer.role == FindingReceiptRole::Production {
            signer.policy.key = keypair(9).public_key();
        }
    }
    profile_body.profile_id = compute_profile_id(&profile_body)?;
    trust.profile = SignedExportEnvelope::sign(profile_body, &keypair(1))?;
    let draft =
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::ReceiptAuthenticity),
        Some(FindingFacetOutcome::Failed)
    );
    Ok(())
}

#[test]
fn guarantee_consistency_denies_an_unbacked_metered_claim() -> TestResult {
    let fx = metered_attested_fixture()?;
    let trust = trust_roots(&fx);
    let draft =
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;
    // Signed nonce evidence is present, but the kernel-accounted spend is
    // below the Finding's asserted evidence cost.
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::MeteredExposureBacking),
        Some(FindingFacetOutcome::Failed)
    );
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::GuaranteeConsistency),
        Some(FindingFacetOutcome::Failed)
    );
    Ok(())
}
