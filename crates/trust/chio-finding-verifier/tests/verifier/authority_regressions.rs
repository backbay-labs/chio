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
    assert!(draft.backing_allocation_id().is_none());
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
        .facets()
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::BondBacking)
        .ok_or("bond-backing facet missing")?;
    assert_eq!(backing.outcome, FindingFacetOutcome::Failed);
    assert!(backing.reason.contains("before its signed issue time"));
    assert!(draft.backing_allocation_id().is_none());
    Ok(())
}

#[test]
fn bond_backing_requires_live_unrevoked_collateral_authority_standing() -> TestResult {
    let fx = fixture()?;

    let mut revoked = trust_roots(&fx);
    let trusted_time = revoked.trusted_time;
    let collateral_authority_id = revoked.collateral_authority.authority_id.clone();
    let status = revoked
        .checkpoint_signer_status
        .as_mut()
        .ok_or("missing signer-status trust")?
        .signed_statuses
        .iter_mut()
        .find(|status| status.body.authority_id == collateral_authority_id)
        .ok_or("collateral authority status missing")?;
    status.body.revoked_from = Some(trusted_time);
    *status = SignedExportEnvelope::sign(status.body.clone(), &fx.checkpoint_status_authority)?;
    let draft =
        verify_finding_evidence(&fx.raw_finding, &revoked, &bundle(&fx, clone_receipts(&fx)))?;
    let backing = draft
        .facets()
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::BondBacking)
        .ok_or("bond-backing facet missing")?;
    assert_eq!(backing.outcome, FindingFacetOutcome::Failed);
    assert!(backing.reason.contains("is revoked"));
    assert!(draft.backing_allocation_id().is_none());

    let mut expired = trust_roots(&fx);
    expired.collateral_authority.valid_until = expired.trusted_time;
    let draft =
        verify_finding_evidence(&fx.raw_finding, &expired, &bundle(&fx, clone_receipts(&fx)))?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::BondBacking),
        Some(FindingFacetOutcome::Failed)
    );
    assert!(draft.backing_allocation_id().is_none());
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
        .facets()
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::BondBacking)
        .ok_or("bond-backing facet missing")?;
    assert_eq!(backing.outcome, FindingFacetOutcome::Failed);
    assert!(
        backing.reason.contains("evaluated verifier profile"),
        "unexpected reason: {}",
        backing.reason
    );
    assert!(draft.backing_allocation_id().is_none());
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
fn revoked_profile_governance_authority_cannot_backdate_a_profile() -> TestResult {
    let fx = fixture()?;
    let mut trust = trust_roots(&fx);
    let revoked = SignedExportEnvelope::sign(
        FindingAuthorityStatus {
            schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.to_owned(),
            status_ref: trust
                .governance_authority_policy
                .revocation_status_ref
                .clone(),
            authority_id: trust.governance_authority_policy.authority_id.clone(),
            key: trust.governance_authority_policy.key.clone(),
            key_epoch: trust.governance_authority_policy.key_epoch,
            revoked_from: Some(1_749_999_999),
            observed_at: trust.trusted_time,
        },
        &fx.checkpoint_status_authority,
    )?;
    let governance_authority_id = trust.governance_authority_policy.authority_id.clone();
    let status = trust
        .checkpoint_signer_status
        .as_mut()
        .ok_or("status trust missing")?;
    status
        .signed_statuses
        .retain(|signed| signed.body.authority_id != governance_authority_id);
    status.signed_statuses.push(revoked);

    assert_eq!(
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx))).err(),
        Some(FindingVerifierError::ProfileInvalid)
    );
    Ok(())
}

#[test]
fn report_signing_key_must_be_distinct_from_governance_and_evidence() -> TestResult {
    let fx = fixture()?;
    let trusted = trust_roots(&fx);
    let draft =
        verify_finding_evidence(&fx.raw_finding, &trusted, &bundle(&fx, clone_receipts(&fx)))?;

    let mut profile = fx.profile.body.clone();
    profile.verifier_report_signer.key = fx.governance.public_key();
    profile.profile_id = compute_profile_id(&profile)?;
    assert_eq!(
        validate_supported_finding_verifier_profile(&profile).err(),
        Some(FindingVerifierError::ProfileInvalid)
    );

    let mut aliased = trust_roots(&fx);
    aliased.profile = SignedExportEnvelope::sign(profile, &fx.governance)?;
    assert_eq!(
        verify_finding_evidence(&fx.raw_finding, &aliased, &bundle(&fx, clone_receipts(&fx))).err(),
        Some(FindingVerifierError::ProfileInvalid)
    );
    assert_eq!(
        sign_finding_verifier_report(
            &draft,
            &aliased,
            "chio-finding-verifier/0.1",
            &fx.governance,
        )
        .err(),
        Some(FindingVerifierError::ProfileInvalid)
    );

    let mut receipt_aliased = fx.profile.body.clone();
    receipt_aliased.verifier_report_signer.key = receipt_aliased
        .receipt_signers
        .first()
        .ok_or("fixture receipt signer is missing")?
        .policy
        .key
        .clone();
    assert_eq!(
        validate_supported_finding_verifier_profile(&receipt_aliased).err(),
        Some(FindingVerifierError::ProfileInvalid)
    );

    let mut checkpoint_aliased = fx.profile.body.clone();
    checkpoint_aliased.verifier_report_signer.key = checkpoint_aliased
        .checkpoint_logs
        .first()
        .ok_or("fixture checkpoint signer is missing")?
        .signer
        .key
        .clone();
    assert_eq!(
        validate_supported_finding_verifier_profile(&checkpoint_aliased).err(),
        Some(FindingVerifierError::ProfileInvalid)
    );

    let mut evidence_roles_aliased = fx.profile.body.clone();
    evidence_roles_aliased.checkpoint_logs[0].signer.key = evidence_roles_aliased
        .receipt_signers
        .first()
        .ok_or("fixture receipt signer is missing")?
        .policy
        .key
        .clone();
    assert_eq!(
        validate_supported_finding_verifier_profile(&evidence_roles_aliased).err(),
        Some(FindingVerifierError::ProfileInvalid)
    );
    Ok(())
}

#[test]
fn runtime_attestation_and_appraisal_authorities_must_be_distinct() -> TestResult {
    let fx = runtime_fixture(RuntimeAssuranceTier::Verified)?;
    let mut trust = runtime_trust_roots(&fx);
    trust.appraisal_authority = trust.runtime_attestation_authority.clone();

    assert_eq!(
        verify_finding_evidence(&fx.fixture.raw_finding, &trust, &runtime_bundle(&fx),).err(),
        Some(FindingVerifierError::AliasedRuntimeAssuranceAuthorities)
    );
    Ok(())
}

#[test]
fn verifier_report_and_collateral_authorities_must_be_distinct() -> TestResult {
    let fx = fixture()?;
    let mut trust = trust_roots(&fx);
    trust.collateral_authority.key = trust.profile.body.verifier_report_signer.key.clone();

    assert_eq!(
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx))).err(),
        Some(FindingVerifierError::AliasedVerifierAndCollateralAuthorities)
    );
    Ok(())
}

#[test]
fn fee_schedule_and_collateral_authorities_must_be_distinct() -> TestResult {
    let fx = fixture()?;
    let mut trust = trust_roots(&fx);
    trust
        .fee_schedule_authorities
        .push(trust.collateral_authority.key.clone());

    assert_eq!(
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx))).err(),
        Some(FindingVerifierError::AliasedFeeScheduleAndCollateralAuthorities)
    );
    Ok(())
}

#[test]
fn verifier_report_and_status_operator_authorities_must_be_distinct() -> TestResult {
    let fx = fixture()?;
    let finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    let (_, mut authorization, freshness) = portable_live_status_proof(&finding.finding_id)?;
    authorization.operator.key = fx.profile.body.verifier_report_signer.key.clone();

    let mut trust = trust_roots(&fx);
    trust.status_operator_authorization = Some(authorization);
    trust.status_freshness_policy = Some(freshness);

    assert_eq!(
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx))).err(),
        Some(FindingVerifierError::AliasedVerifierAndStatusOperatorAuthorities)
    );
    Ok(())
}

#[test]
fn verifier_report_and_authority_status_signers_must_be_distinct() -> TestResult {
    let fx = fixture()?;
    let mut trust = trust_roots(&fx);
    trust
        .checkpoint_signer_status
        .as_mut()
        .ok_or("missing authority-status trust")?
        .status_authority
        .key = trust.profile.body.verifier_report_signer.key.clone();

    assert_eq!(
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx))).err(),
        Some(FindingVerifierError::AliasedVerifierAndStatusAuthority)
    );
    Ok(())
}

#[test]
fn runtime_assurance_requires_live_unrevoked_authority_standing() -> TestResult {
    let fx = runtime_fixture(RuntimeAssuranceTier::Verified)?;

    for authority_id in [
        fx.attestation_authority_policy.authority_id.as_str(),
        fx.appraisal_authority_policy.authority_id.as_str(),
    ] {
        let mut trust = runtime_trust_roots(&fx);
        let trusted_time = trust.trusted_time;
        let status = trust
            .checkpoint_signer_status
            .as_mut()
            .ok_or("missing signer-status trust")?
            .signed_statuses
            .iter_mut()
            .find(|status| status.body.authority_id == authority_id)
            .ok_or("runtime authority status missing")?;
        status.body.revoked_from = Some(trusted_time);
        *status = SignedExportEnvelope::sign(
            status.body.clone(),
            &fx.fixture.checkpoint_status_authority,
        )?;

        let draft = verify_finding_evidence(&fx.fixture.raw_finding, &trust, &runtime_bundle(&fx))?;
        let assurance = draft
            .facets()
            .iter()
            .find(|facet| facet.facet == FindingFacetKind::RuntimeAssuranceBacking)
            .ok_or("runtime-assurance facet missing")?;
        assert_eq!(assurance.outcome, FindingFacetOutcome::Failed);
        assert!(assurance.reason.contains("is revoked"));
        assert!(!draft.satisfies_required_facets(&fx.fixture.profile.body));
    }

    let mut expired = runtime_trust_roots(&fx);
    let trusted_time = expired.trusted_time;
    expired
        .runtime_attestation_authority
        .as_mut()
        .ok_or("runtime-attestation policy missing")?
        .valid_until = trusted_time;
    let draft = verify_finding_evidence(&fx.fixture.raw_finding, &expired, &runtime_bundle(&fx))?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::RuntimeAssuranceBacking),
        Some(FindingFacetOutcome::Failed)
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
    assert_eq!(
        validate_supported_finding_verifier_profile(&profile).err(),
        Some(FindingVerifierError::ProfileInvalid)
    );
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
    signing_trust.collateral_authority.key = keypair(44).public_key();
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
fn recipe_preimage_must_fit_its_committed_size_bound() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let profile_sha256 = sha256_hex(&canonical_json_bytes(&fx.profile)?);
    let mut bounded = recipe(HEX64, &fx.finding_payload_sha256, &profile_sha256, HEX64);
    bounded.resource_bounds.max_recipe_bytes = 1;
    let bounded_bytes = canonical_json_bytes(&bounded)?;

    let mut finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    finding.replay_recipe_sha256 = Some(sha256_hex(&bounded_bytes));
    finding.signature.clear();
    finding.finding_id = compute_finding_id(&finding)?;
    let finding = sign_finding(finding, &fx.issuer)?;
    let raw_finding = String::from_utf8(canonical_json_bytes(&finding)?)?;

    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.recipe_preimage = Some(&bounded_bytes);
    let draft = verify_finding_evidence(&raw_finding, &trust, &evidence)?;
    let binding = draft
        .facets()
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::RecipeBinding)
        .ok_or("recipe-binding facet missing")?;
    assert_eq!(binding.outcome, FindingFacetOutcome::Failed);
    assert!(binding.reason.contains("committed size bound"));
    Ok(())
}

#[test]
fn backing_signed_by_an_unpinned_authority_is_not_bond_evidence() -> TestResult {
    let fx = fixture()?;
    let mut trust = trust_roots(&fx);
    trust.collateral_authority.key = keypair(9).public_key();
    let draft =
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::BondBacking),
        Some(FindingFacetOutcome::Failed)
    );
    assert!(draft.backing_allocation_id().is_none());
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
