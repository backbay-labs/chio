const LISTING_ID: &str = "listing-qualified-transaction";
const RESERVATION_ID: &str = "reservation-qualified-transaction";

fn purchase_authority_keypair() -> Keypair {
    Keypair::from_seed(&[11_u8; 32])
}

fn purchase_authority_status(
    profile: &SignedFindingChallengeVerifierProfile,
    status_authority: &Keypair,
) -> TestResult<SignedExportEnvelope<FindingAuthorityStatus>> {
    let policy = &profile.body.purchase_authority;
    Ok(SignedExportEnvelope::sign(
        FindingAuthorityStatus {
            schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.to_owned(),
            status_ref: policy.revocation_status_ref.clone(),
            authority_id: policy.authority_id.clone(),
            key: policy.key.clone(),
            key_epoch: policy.key_epoch,
            revoked_from: None,
            observed_at: CHECKED_AT,
        },
        status_authority,
    )?)
}

fn finding_delivery_overlay() -> FindingDelivery {
    FindingDelivery {
        schema: FINDING_DELIVERY_SCHEMA.to_owned(),
        finding_id: FINDING_ID.to_owned(),
        listing_id: LISTING_ID.to_owned(),
        transform_profile: FindingTransformProfile::Identity,
        digest_check: DeliveryResult::Matched,
        media_type_check: FindingMediaTypeCheck::Matched,
        settlement_mode: FindingDeliverySettlementMode::LocalReversibleHold,
        accepted_bid_envelope_sha256: "ab".repeat(32),
        venue_admission_envelope_sha256: "cd".repeat(32),
        reservation_id: RESERVATION_ID.to_owned(),
        purchase_intent_id: derive_purchase_intent_id(RESERVATION_ID),
        authoritative_payment_operation_id: derive_payment_operation_id(RESERVATION_ID),
        status_proof: None,
    }
}

fn purchase_record_bytes() -> TestResult<Vec<u8>> {
    let delivery = finding_delivery_overlay();
    let purchase = FindingPurchaseRecord {
        schema: FINDING_PURCHASE_RECORD_SCHEMA_V1.to_owned(),
        purchase_key: derive_purchase_key(
            &delivery.accepted_bid_envelope_sha256,
            &delivery.authoritative_payment_operation_id,
        ),
        purchase_intent_id: delivery.purchase_intent_id.clone(),
        authoritative_payment_operation_id: delivery.authoritative_payment_operation_id.clone(),
        buyer: Keypair::from_seed(&[12_u8; 32]).public_key(),
        payer: Keypair::from_seed(&[13_u8; 32]).public_key(),
        finding_id: delivery.finding_id.clone(),
        listing_id: delivery.listing_id.clone(),
        accepted_bid_envelope_sha256: delivery.accepted_bid_envelope_sha256.clone(),
        venue_admission_envelope_sha256: delivery.venue_admission_envelope_sha256.clone(),
        accepted_price: MonetaryAmount {
            units: 50,
            currency: "USD".to_owned(),
        },
        realized_spend: MonetaryAmount {
            units: 50,
            currency: "USD".to_owned(),
        },
        seller_backing_envelope_sha256: "ef".repeat(32),
        encumbrance_id: "encumbrance-qualified-transaction".to_owned(),
        delivery_receipt_id: "89".repeat(32),
        payment_reference: delivery.authoritative_payment_operation_id.clone(),
        payout_destination: "0x1111111111111111111111111111111111111111".to_owned(),
        recorded_at: CHECKED_AT,
    };
    purchase.validate()?;
    let signed = SignedExportEnvelope::sign(purchase, &purchase_authority_keypair())?;
    Ok(canonical_json_bytes(&signed)?)
}

fn replace_purchase_record(
    bundle: &mut QualifiedBundle,
    mutate: impl FnOnce(&mut FindingPurchaseRecord),
) -> TestResult {
    let signed: SignedExportEnvelope<FindingPurchaseRecord> = serde_json::from_slice(
        bundle
            .artifacts
            .get("purchase-record.json")
            .ok_or("purchase record missing")?,
    )?;
    let mut record = signed.body;
    mutate(&mut record);
    record.validate()?;
    let signed = SignedExportEnvelope::sign(record, &purchase_authority_keypair())?;
    replace_graph_artifact(
        bundle,
        "purchase-record.json",
        canonical_json_bytes(&signed)?,
    )?;
    resign_graph(bundle)
}

#[test]
fn cognition_market_delivery_claim_rejects_a_pre_sale_report() -> TestResult {
    let mut bundle = build_bundle()?;
    let report_bytes = bundle
        .artifacts
        .get("report.json")
        .ok_or("report missing")?;
    let signed: SignedExportEnvelope<FindingVerifierReport> = serde_json::from_slice(report_bytes)?;
    let mut report = signed.body;
    report.finding_delivery_receipt_id = None;
    report.finding_delivery = None;
    report.report_id = compute_report_id(&report)?;
    let replacement = SignedExportEnvelope::sign(report, &verifier_keypair())?;
    replace_graph_artifact(
        &mut bundle,
        "report.json",
        canonical_json_bytes(&replacement)?,
    )?;
    resign_graph(&mut bundle)?;

    let error = verify(&bundle)
        .err()
        .ok_or("pre-sale report granted a delivery-bound claim")?
        .to_string();
    assert!(
        error.contains("has no authenticated delivery receipt id"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_delivery_claim_rejects_cross_purchase_report_identity() -> TestResult {
    for field in [
        "listing",
        "accepted_bid",
        "admission",
        "reservation",
        "purchase_intent",
        "payment_operation",
        "delivery_receipt",
    ] {
        let mut bundle = build_bundle()?;
        let report_bytes = bundle
            .artifacts
            .get("report.json")
            .ok_or("report missing")?;
        let signed: SignedExportEnvelope<FindingVerifierReport> =
            serde_json::from_slice(report_bytes)?;
        let mut report = signed.body;
        let delivery = report
            .finding_delivery
            .as_mut()
            .ok_or("delivery overlay missing")?;
        match field {
            "listing" => delivery.listing_id = "listing-from-an-older-sale".to_owned(),
            "accepted_bid" => delivery.accepted_bid_envelope_sha256 = "bc".repeat(32),
            "admission" => delivery.venue_admission_envelope_sha256 = "de".repeat(32),
            "reservation" => delivery.reservation_id = "reservation-from-an-older-sale".to_owned(),
            "purchase_intent" => delivery.purchase_intent_id = "old-purchase-intent".to_owned(),
            "payment_operation" => {
                delivery.authoritative_payment_operation_id = "old-payment-operation".to_owned();
            }
            "delivery_receipt" => report.finding_delivery_receipt_id = Some("98".repeat(32)),
            _ => return Err("unhandled transaction identity field".into()),
        }
        report.report_id = compute_report_id(&report)?;
        let replacement = SignedExportEnvelope::sign(report, &verifier_keypair())?;
        replace_graph_artifact(
            &mut bundle,
            "report.json",
            canonical_json_bytes(&replacement)?,
        )?;
        resign_graph(&mut bundle)?;

        let error = verify(&bundle)
            .err()
            .ok_or("cross-purchase report identity granted a delivery-bound claim")?
            .to_string();
        assert!(
            error.contains("does not bind the passport purchase transaction"),
            "unexpected {field} error: {error}"
        );
    }
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_rejects_purchase_authority_as_passport_signer() -> TestResult
{
    let mut bundle = build_bundle()?;
    bundle.trust.trusted_passport_signer_keys = vec![bundle.trust.purchase_authority.clone()];

    let error = verify(&bundle)
        .err()
        .ok_or("purchase authority was accepted as a passport signer")?
        .to_string();
    assert!(
        error.contains("passport signer and purchase-record authorities must be distinct"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_rejects_purchase_authority_outside_profile() -> TestResult {
    let mut bundle = build_bundle()?;
    bundle.trust.purchase_authority = Keypair::from_seed(&[14_u8; 32]).public_key();

    let error = verify(&bundle)
        .err()
        .ok_or("purchase authority outside the governance-signed profile was accepted")?
        .to_string();
    assert!(
        error.contains("pinned verifier profile purchase authority and deployment key disagree"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_delivery_claim_requires_purchase_authority_standing() -> TestResult {
    let mut bundle = build_bundle()?;
    bundle.trust.purchase_authority_status = None;

    let error = verify(&bundle)
        .err()
        .ok_or("delivery claim without purchase-authority standing was accepted")?
        .to_string();
    assert!(
        error.contains("requires current authenticated purchase-authority standing"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_purchase_record_must_fall_within_the_pinned_authority_lifecycle() -> TestResult {
    let mut bundle = build_bundle()?;
    let valid_from = bundle
        .trust
        .trusted_verifier_profile
        .body
        .purchase_authority
        .valid_from;
    replace_purchase_record(&mut bundle, |record| {
        record.recorded_at = valid_from.saturating_sub(1);
    })?;

    let error = verify(&bundle)
        .err()
        .ok_or("out-of-window purchase record was accepted")?
        .to_string();
    assert!(
        error.contains("purchase-authority lifecycle"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_rejects_unanchored_purchase_after_authority_expiry() -> TestResult {
    let mut bundle = build_bundle()?;
    replace_trusted_profile(&mut bundle, |profile| {
        profile.purchase_authority.valid_until = CHECKED_AT;
    })?;

    let error = verify(&bundle)
        .err()
        .ok_or("purchase record under an expired authority was accepted")?
        .to_string();
    assert!(
        error.contains("after purchase-authority key expiration"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_rejects_unanchored_purchase_after_authority_revocation() -> TestResult {
    let mut bundle = build_bundle()?;
    let purchase_status = bundle
        .trust
        .purchase_authority_status
        .as_mut()
        .ok_or("purchase authority status missing")?;
    let mut standing = purchase_status.signed_status.body.clone();
    standing.revoked_from = Some(CHECKED_AT);
    purchase_status.signed_status =
        SignedExportEnvelope::sign(standing, &Keypair::from_seed(&[10_u8; 32]))?;

    let error = verify(&bundle)
        .err()
        .ok_or("purchase record under a revoked authority was accepted")?
        .to_string();
    assert!(
        error.contains("after purchase-authority key revocation"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn claim_set_schema_requires_a_subject_for_finding_claims() -> TestResult {
    let schema_path =
        workspace_root().join("spec/schemas/chio-transaction/v1/claim-set.schema.json");
    let schema: Value = serde_json::from_slice(&std::fs::read(schema_path)?)?;
    let validator = jsonschema::validator_for(&schema)?;
    let claim = |claim_id: &str| {
        json!({
            "schema": "chio.transaction.claim-set.v1",
            "id": "claim-set-schema-regression",
            "issued_at": "2026-08-14T00:00:00Z",
            "claims": [{
                "claim_id": claim_id,
                "status": "verified",
                "required_evidence": ["report.json"],
                "evidence_refs": ["report.json"],
                "verifier_module": "chio proof verify"
            }]
        })
    };

    assert!(validator.is_valid(&claim("claim.agent_web.digest_bound")));
    assert!(!validator.is_valid(&claim(COGNITION_MARKET_CLAIMS[0])));
    Ok(())
}
