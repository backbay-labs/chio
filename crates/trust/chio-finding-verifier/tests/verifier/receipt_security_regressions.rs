use super::*;
use chio_finding::FindingFacetResult;
use chio_finding_verifier::FindingVerifierDraft;

pub(super) fn receipt_signer_statuses(
    profile: &SignedExportEnvelope<FindingChallengeVerifierProfile>,
    status_authority: &Keypair,
) -> Result<Vec<SignedFindingAuthorityStatus>, Box<dyn Error>> {
    profile
        .body
        .receipt_signers
        .iter()
        .filter(|signer| {
            matches!(
                signer.role,
                FindingReceiptRole::Production | FindingReceiptRole::Delivery
            )
        })
        .map(|signer| {
            Ok(SignedExportEnvelope::sign(
                FindingAuthorityStatus {
                    schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.to_string(),
                    status_ref: signer.policy.revocation_status_ref.clone(),
                    authority_id: signer.policy.authority_id.clone(),
                    key: signer.policy.key.clone(),
                    key_epoch: signer.policy.key_epoch,
                    revoked_from: None,
                    observed_at: 1_750_000_010,
                },
                status_authority,
            )?)
        })
        .collect()
}

fn receipt_authenticity(draft: &FindingVerifierDraft) -> Result<&FindingFacetResult, String> {
    draft
        .facets
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::ReceiptAuthenticity)
        .ok_or_else(|| "receipt-authenticity facet missing".to_string())
}

#[test]
fn production_receipt_rejects_nonce_expired_at_receipt_issuance() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let mut nonces = fx.nonce_resolver.nonces.clone();
    let nonce = nonces.first_mut().ok_or("production nonce missing")?;
    nonce.nonce.expires_at = i64::try_from(fx.receipts[0].receipt.timestamp)?;
    nonce.signature = keypair(21).sign(&canonical_json_bytes(&nonce.nonce)?);
    let resolver = TestNonceResolver { nonces };
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.nonce_resolver = &resolver;

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    let authenticity = receipt_authenticity(&draft)?;
    assert_eq!(authenticity.outcome, FindingFacetOutcome::Failed);
    assert!(authenticity
        .reason
        .contains("execution nonce was not active at receipt issuance"));
    Ok(())
}

#[test]
fn delivery_receipt_rejects_nonce_expired_at_receipt_issuance() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    let delivery = resolved_delivery(
        &fx,
        &finding.payload_sha256,
        Some(finding_delivery_overlay(&finding.finding_id)),
    )?;
    let delivery_timestamp = delivery.receipt.receipt.timestamp;
    let mut resolver = nonce_resolver_with_delivery(&fx, &delivery)?;
    let nonce = resolver.nonces.last_mut().ok_or("delivery nonce missing")?;
    nonce.nonce.expires_at = i64::try_from(delivery_timestamp)?;
    nonce.signature = keypair(12).sign(&canonical_json_bytes(&nonce.nonce)?);
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.finding_delivery = Some(delivery);
    evidence.nonce_resolver = &resolver;

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    let authenticity = receipt_authenticity(&draft)?;
    assert_eq!(authenticity.outcome, FindingFacetOutcome::Failed);
    assert!(authenticity
        .reason
        .contains("execution nonce was not active at receipt issuance"));
    Ok(())
}

#[test]
fn delivery_nonce_envelope_changes_the_bundle_commitment() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    let overlay = finding_delivery_overlay(&finding.finding_id);

    let delivery = resolved_delivery(&fx, &finding.payload_sha256, Some(overlay.clone()))?;
    let baseline_resolver = nonce_resolver_with_delivery(&fx, &delivery)?;
    let mut baseline_evidence = bundle(&fx, clone_receipts(&fx));
    baseline_evidence.finding_delivery = Some(delivery);
    baseline_evidence.nonce_resolver = &baseline_resolver;
    let baseline = verify_finding_evidence(&fx.raw_finding, &trust, &baseline_evidence)?;

    let changed_delivery = resolved_delivery(&fx, &finding.payload_sha256, Some(overlay))?;
    let mut changed_resolver = nonce_resolver_with_delivery(&fx, &changed_delivery)?;
    let changed_nonce = changed_resolver
        .nonces
        .last_mut()
        .ok_or("delivery nonce missing")?;
    changed_nonce.nonce.expires_at = changed_nonce.nonce.expires_at.saturating_add(1);
    changed_nonce.signature = keypair(12).sign(&canonical_json_bytes(&changed_nonce.nonce)?);
    let mut changed_evidence = bundle(&fx, clone_receipts(&fx));
    changed_evidence.finding_delivery = Some(changed_delivery);
    changed_evidence.nonce_resolver = &changed_resolver;
    let changed = verify_finding_evidence(&fx.raw_finding, &trust, &changed_evidence)?;

    assert_eq!(
        baseline.facet_outcome(FindingFacetKind::ReceiptAuthenticity),
        Some(FindingFacetOutcome::Verified)
    );
    assert_eq!(
        changed.facet_outcome(FindingFacetKind::ReceiptAuthenticity),
        Some(FindingFacetOutcome::Verified)
    );
    assert_ne!(
        baseline.resolved_evidence_bundle_sha256,
        changed.resolved_evidence_bundle_sha256
    );
    Ok(())
}

#[test]
fn revoked_production_receipt_signer_is_rejected() -> TestResult {
    let fx = fixture()?;
    let mut trust = trust_roots(&fx);
    let status_trust = trust
        .checkpoint_signer_status
        .as_mut()
        .ok_or("signer status trust missing")?;
    let signed_status = status_trust
        .signed_statuses
        .iter_mut()
        .find(|signed| signed.body.authority_id == "authority-production")
        .ok_or("production signer status missing")?;
    signed_status.body.revoked_from = Some(signed_status.body.observed_at.saturating_sub(1));
    signed_status.signature = fx
        .checkpoint_status_authority
        .sign(&canonical_json_bytes(&signed_status.body)?);

    let draft =
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;
    let authenticity = receipt_authenticity(&draft)?;
    assert_eq!(authenticity.outcome, FindingFacetOutcome::Failed);
    assert!(authenticity.reason.contains("receipt signer is revoked"));
    Ok(())
}

#[test]
fn production_receipt_rejects_signer_expired_at_evaluation() -> TestResult {
    let fx = fixture()?;
    let mut trust = trust_roots(&fx);
    let mut profile = fx.profile.body.clone();
    let production = profile
        .receipt_signers
        .iter_mut()
        .find(|signer| signer.role == FindingReceiptRole::Production)
        .ok_or("production signer policy missing")?;
    production.policy.valid_until = trust.trusted_time;
    trust.profile = resign_profile(profile)?;

    let draft =
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;
    let authenticity = receipt_authenticity(&draft)?;
    assert_eq!(authenticity.outcome, FindingFacetOutcome::Failed);
    assert!(authenticity
        .reason
        .contains("receipt signer authority expired before evaluation"));
    Ok(())
}

#[test]
fn delivery_receipt_rejects_signer_expired_at_evaluation() -> TestResult {
    let fx = fixture()?;
    let mut trust = trust_roots(&fx);
    let mut profile = fx.profile.body.clone();
    let delivery_policy = profile
        .receipt_signers
        .iter_mut()
        .find(|signer| signer.role == FindingReceiptRole::Delivery)
        .ok_or("delivery signer policy missing")?;
    delivery_policy.policy.valid_until = trust.trusted_time;
    trust.profile = resign_profile(profile)?;
    let finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    let delivery = resolved_delivery(
        &fx,
        &finding.payload_sha256,
        Some(finding_delivery_overlay(&finding.finding_id)),
    )?;
    let resolver = nonce_resolver_with_delivery(&fx, &delivery)?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.finding_delivery = Some(delivery);
    evidence.nonce_resolver = &resolver;

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    let authenticity = receipt_authenticity(&draft)?;
    assert_eq!(authenticity.outcome, FindingFacetOutcome::Failed);
    assert!(authenticity
        .reason
        .contains("receipt signer authority expired before evaluation"));
    Ok(())
}

#[test]
fn missing_delivery_receipt_signer_status_is_rejected() -> TestResult {
    let fx = fixture()?;
    let mut trust = trust_roots(&fx);
    trust
        .checkpoint_signer_status
        .as_mut()
        .ok_or("signer status trust missing")?
        .signed_statuses
        .retain(|signed| signed.body.authority_id != "authority-delivery");
    let finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    let delivery = resolved_delivery(
        &fx,
        &finding.payload_sha256,
        Some(finding_delivery_overlay(&finding.finding_id)),
    )?;
    let resolver = nonce_resolver_with_delivery(&fx, &delivery)?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.finding_delivery = Some(delivery);
    evidence.nonce_resolver = &resolver;

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    let authenticity = receipt_authenticity(&draft)?;
    assert_eq!(authenticity.outcome, FindingFacetOutcome::Failed);
    assert!(authenticity
        .reason
        .contains("receipt signer status evidence not supplied"));
    Ok(())
}
