use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::sha256_hex;
use chio_credit::factor::{
    AssignmentOfferV1, DiscountQuoteOutcomeV1, DiscountQuoteV1, FactorError,
    NormalizedAssignmentRequestInputV1, NormalizedAssignmentRequestV1, ReceivableClaimInputV1,
    ReceivableClaimV1,
};
use chio_credit::obligation::derive_obligation_payee_binding_digest;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn validate_schema(name: &str, artifact: &impl serde::Serialize) -> TestResult {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-economy")
        .join(name);
    let schema = chio_spec_validate::load_json(&path)?;
    chio_spec_validate::validate_value(
        &path,
        &schema,
        &std::path::PathBuf::from("<factor-contract>"),
        &serde_json::to_value(artifact)?,
    )?;
    Ok(())
}

fn claim_with(
    units: u64,
    currency: &str,
    built_at_unix_ms: u64,
    due_at_unix_ms: u64,
) -> Result<ReceivableClaimV1, FactorError> {
    ReceivableClaimV1::new(ReceivableClaimInputV1 {
        obligation_id: digest("obligation"),
        obligation_atom_digest: digest("obligation-atom"),
        seller_id: "did:chio:seller".to_owned(),
        receipt_id: "receipt-1".to_owned(),
        receipt_digest: digest("receipt"),
        iou_id: "iou-1".to_owned(),
        iou_digest: digest("iou"),
        payee_binding_digest: derive_obligation_payee_binding_digest(
            "did:chio:seller",
            "acct:seller",
        )
        .map_err(|_| FactorError::InvalidField("payee_binding_digest"))?,
        status_proof_digest: digest("status-proof"),
        face_value: MonetaryAmount {
            units,
            currency: currency.to_owned(),
        },
        due_at_unix_ms,
        built_at_unix_ms,
    })
}

fn request_with(
    claim: &ReceivableClaimV1,
    offer: &AssignmentOfferV1,
    buyer_id: &str,
    disposition_fence: u64,
    expires_at_unix_ms: u64,
) -> Result<NormalizedAssignmentRequestV1, FactorError> {
    NormalizedAssignmentRequestV1::new(NormalizedAssignmentRequestInputV1 {
        obligation_id: claim.obligation_id().to_owned(),
        obligation_atom_digest: claim.obligation_atom_digest().to_owned(),
        claim_digest: claim.digest()?,
        offer_digest: offer.digest()?,
        seller_id: claim.seller_id().to_owned(),
        buyer_id: buyer_id.to_owned(),
        buyer_settlement_destination_ref: "acct:buyer".to_owned(),
        agreed_price: offer.minimum_price().clone(),
        agreed_discount_bps: offer.asking_discount_bps(),
        expected_disposition_version: 3,
        expected_disposition_lifecycle_fence: disposition_fence,
        expected_settlement_lifecycle_version: 4,
        expected_settlement_lifecycle_fence: 4,
        action_nonce: "assignment-nonce-1".to_owned(),
        effective_at_unix_ms: 500,
        due_at_unix_ms: claim.due_at_unix_ms(),
        expires_at_unix_ms,
    })
}

#[test]
fn factor_artifacts_are_strict_canonical_and_schema_valid() -> TestResult {
    let claim = claim_with(1_001, "USD", 100, 1_000)?;
    let offer = AssignmentOfferV1::new(&claim, 1_000, 200, 900)?;
    let quote = DiscountQuoteV1::quoted(
        &claim,
        digest("underwriting-decision"),
        digest("scorecard"),
        1_000,
    )?;
    let request = request_with(&claim, &offer, "did:chio:buyer", 3, 800)?;

    validate_schema("factor-receivable-claim.v1.json", &claim)?;
    validate_schema("factor-assignment-offer.v1.json", &offer)?;
    validate_schema("factor-discount-quote.v1.json", &quote)?;
    validate_schema("factor-normalized-assignment-request.v1.json", &request)?;

    assert_eq!(
        serde_json::from_slice::<ReceivableClaimV1>(&claim.canonical_bytes()?)?,
        claim
    );
    assert_eq!(
        serde_json::from_slice::<AssignmentOfferV1>(&offer.canonical_bytes()?)?,
        offer
    );
    assert_eq!(
        serde_json::from_slice::<DiscountQuoteV1>(&quote.canonical_bytes()?)?,
        quote
    );
    assert_eq!(
        serde_json::from_slice::<NormalizedAssignmentRequestV1>(&request.canonical_bytes()?)?,
        request
    );
    assert_eq!(claim.claim_id().len(), 64);
    assert_eq!(offer.offer_id().len(), 64);
    assert_eq!(quote.quote_id().len(), 64);
    assert_eq!(request.digest()?.len(), 64);

    let mut unknown = serde_json::to_value(&request)?;
    unknown["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<NormalizedAssignmentRequestV1>(unknown).is_err());

    let mut unknown = serde_json::to_value(&claim)?;
    unknown["schema"] = serde_json::json!("chio.factor.receivable-claim.v9");
    assert_eq!(
        serde_json::from_value::<ReceivableClaimV1>(unknown)?.validate(),
        Err(FactorError::InvalidField("claim_schema"))
    );
    let mut unknown = serde_json::to_value(&offer)?;
    unknown["schema"] = serde_json::json!("chio.factor.assignment-offer.v9");
    assert_eq!(
        serde_json::from_value::<AssignmentOfferV1>(unknown)?.validate(),
        Err(FactorError::InvalidField("offer_schema"))
    );
    let mut unknown = serde_json::to_value(&quote)?;
    unknown["schema"] = serde_json::json!("chio.factor.discount-quote.v9");
    assert_eq!(
        serde_json::from_value::<DiscountQuoteV1>(unknown)?.validate(),
        Err(FactorError::InvalidField("discount_quote_schema"))
    );
    let mut unknown = serde_json::to_value(&request)?;
    unknown["schema"] = serde_json::json!("chio.factor.normalized-assignment-request.v9");
    assert_eq!(
        serde_json::from_value::<NormalizedAssignmentRequestV1>(unknown)?.validate(),
        Err(FactorError::InvalidField("normalized_request_schema"))
    );
    Ok(())
}

#[test]
fn quote_arithmetic_is_checked_integer_flooring() -> TestResult {
    let claim = claim_with(1_001, "USD", 100, 1_000)?;
    for (discount_bps, expected_units) in [(0, 1_001), (3_333, 667), (10_000, 0)] {
        let quote = DiscountQuoteV1::quoted(
            &claim,
            digest("underwriting-decision"),
            digest("scorecard"),
            discount_bps,
        )?;
        assert!(matches!(
            quote.outcome(),
            DiscountQuoteOutcomeV1::Quoted {
                resolved_discount_bps,
                quoted_price,
            } if *resolved_discount_bps == discount_bps
                && quoted_price.units == expected_units
                && quoted_price.currency == "USD"
        ));
    }
    assert_eq!(
        DiscountQuoteV1::quoted(
            &claim,
            digest("underwriting-decision"),
            digest("scorecard"),
            10_001,
        ),
        Err(FactorError::InvalidField("discount_bps"))
    );
    assert_eq!(
        claim_with(u64::MAX, "USD", 100, 1_000),
        Err(FactorError::InvalidField("face_value"))
    );
    Ok(())
}

#[test]
fn claims_offers_quotes_and_requests_fail_closed_on_invalid_terms() -> TestResult {
    assert_eq!(
        claim_with(0, "USD", 100, 1_000),
        Err(FactorError::InvalidField("face_value"))
    );
    assert_eq!(
        claim_with(100, "usd", 100, 1_000),
        Err(FactorError::InvalidField("face_value"))
    );
    assert_eq!(
        claim_with(100, "USD", 1_000, 1_000),
        Err(FactorError::InvalidField("claim_terms"))
    );

    let claim = claim_with(1_001, "USD", 100, 1_000)?;
    assert_eq!(
        AssignmentOfferV1::new(&claim, 10_001, 200, 900),
        Err(FactorError::InvalidField("discount_bps"))
    );
    assert_eq!(
        AssignmentOfferV1::new(&claim, 1_000, 200, 1_000),
        Err(FactorError::InvalidField("offer_terms"))
    );
    assert_eq!(
        DiscountQuoteV1::refused(
            &claim,
            digest("underwriting-decision"),
            digest("scorecard"),
            " refused ".to_owned(),
        ),
        Err(FactorError::InvalidField("refusal_reason"))
    );

    let offer = AssignmentOfferV1::new(&claim, 1_000, 200, 900)?;
    assert_eq!(
        request_with(&claim, &offer, claim.seller_id(), 3, 800),
        Err(FactorError::InvalidField("normalized_request_terms"))
    );
    assert_eq!(
        request_with(&claim, &offer, "did:chio:buyer", 2, 800),
        Err(FactorError::InvalidField("normalized_request_terms"))
    );
    assert_eq!(
        request_with(&claim, &offer, "did:chio:buyer", 3, 1_001),
        Err(FactorError::InvalidField("normalized_request_terms"))
    );
    Ok(())
}

#[test]
fn derived_ids_and_request_digest_cover_economic_terms() -> TestResult {
    let claim = claim_with(1_001, "USD", 100, 1_000)?;
    let offer = AssignmentOfferV1::new(&claim, 1_000, 200, 900)?;
    let quote = DiscountQuoteV1::quoted(
        &claim,
        digest("underwriting-decision"),
        digest("scorecard"),
        1_000,
    )?;
    let request = request_with(&claim, &offer, "did:chio:buyer", 3, 800)?;

    let changed_request = NormalizedAssignmentRequestV1::new(NormalizedAssignmentRequestInputV1 {
        obligation_id: request.obligation_id().to_owned(),
        obligation_atom_digest: request.obligation_atom_digest().to_owned(),
        claim_digest: request.claim_digest().to_owned(),
        offer_digest: request.offer_digest().to_owned(),
        seller_id: request.seller_id().to_owned(),
        buyer_id: request.buyer_id().to_owned(),
        buyer_settlement_destination_ref: request.buyer_settlement_destination_ref().to_owned(),
        agreed_price: MonetaryAmount {
            units: request.agreed_price().units + 1,
            currency: request.agreed_price().currency.clone(),
        },
        agreed_discount_bps: request.agreed_discount_bps(),
        expected_disposition_version: request.expected_disposition_version(),
        expected_disposition_lifecycle_fence: request.expected_disposition_lifecycle_fence(),
        expected_settlement_lifecycle_version: request.expected_settlement_lifecycle_version(),
        expected_settlement_lifecycle_fence: request.expected_settlement_lifecycle_fence(),
        action_nonce: request.action_nonce().to_owned(),
        effective_at_unix_ms: request.effective_at_unix_ms(),
        due_at_unix_ms: request.due_at_unix_ms(),
        expires_at_unix_ms: request.expires_at_unix_ms(),
    })?;
    assert_ne!(request.digest()?, changed_request.digest()?);

    for (artifact, field, error) in [
        (serde_json::to_value(&claim)?, "claimId", "claim_terms"),
        (serde_json::to_value(&offer)?, "offerId", "offer_terms"),
        (serde_json::to_value(&quote)?, "quoteId", "quote_id"),
    ] {
        let mut changed = artifact;
        changed[field] = serde_json::json!(digest("replacement-id"));
        let result = match field {
            "claimId" => serde_json::from_value::<ReceivableClaimV1>(changed)?.validate(),
            "offerId" => serde_json::from_value::<AssignmentOfferV1>(changed)?.validate(),
            _ => serde_json::from_value::<DiscountQuoteV1>(changed)?.validate(),
        };
        assert_eq!(result, Err(FactorError::InvalidField(error)));
    }
    Ok(())
}
