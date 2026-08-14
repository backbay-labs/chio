const LISTING_ID: &str = "listing-qualified-transaction";
const RESERVATION_ID: &str = "reservation-qualified-transaction";

fn purchase_authority_keypair() -> Keypair {
    Keypair::from_seed(&[11_u8; 32])
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
fn cognition_market_qualified_profile_rejects_unpinned_purchase_record() -> TestResult {
    let mut bundle = build_bundle()?;
    bundle.trust.purchase_authority = Keypair::from_seed(&[14_u8; 32]).public_key();

    let error = verify(&bundle)
        .err()
        .ok_or("purchase record signed outside the deployment pin was accepted")?
        .to_string();
    assert!(
        error.contains("purchase-record.json"),
        "unexpected error: {error}"
    );
    Ok(())
}
