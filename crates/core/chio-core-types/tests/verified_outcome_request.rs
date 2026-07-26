use chio_core_types::capability::governance::{
    GovernedTransactionIntent, GovernedTransactionIntentBody, MeteredBillingContext,
    MeteredBillingQuote, MeteredSettlementMode, VerifiedOutcomeRequestV1,
    VERIFIED_OUTCOME_REQUEST_SCHEMA,
};
use chio_core_types::capability::scope::MonetaryAmount;

fn request() -> VerifiedOutcomeRequestV1 {
    VerifiedOutcomeRequestV1 {
        schema: VERIFIED_OUTCOME_REQUEST_SCHEMA.to_owned(),
        listing_id: "listing-1".to_owned(),
        listing_digest: "1".repeat(64),
        provider_binding_digest: "2".repeat(64),
        pricing_id: "3".repeat(64),
        pricing_digest: "4".repeat(64),
        predicate_id: "5".repeat(64),
        predicate_digest: "6".repeat(64),
        sla_digest: Some("7".repeat(64)),
        receiver_binding_digest: "8".repeat(64),
    }
}

fn intent(extension: VerifiedOutcomeRequestV1) -> GovernedTransactionIntent {
    GovernedTransactionIntent {
        id: "intent-1".to_owned(),
        server_id: "server-1".to_owned(),
        tool_name: "tool-1".to_owned(),
        purpose: "verified result".to_owned(),
        max_amount: None,
        commerce: None,
        metered_billing: Some(MeteredBillingContext {
            settlement_mode: MeteredSettlementMode::HoldCapture,
            quote: MeteredBillingQuote {
                quote_id: "quote-1".to_owned(),
                provider: "provider-1".to_owned(),
                billing_unit: "verified_outcome".to_owned(),
                quoted_units: 1,
                quoted_cost: MonetaryAmount {
                    units: 700,
                    currency: "USD".to_owned(),
                },
                issued_at: 100,
                expires_at: Some(200),
            },
            max_billed_units: Some(1),
            verified_outcome: Some(extension),
        }),
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: GovernedTransactionIntentBody::ToolInvocation,
    }
}

#[test]
fn verified_outcome_extension_is_canonical_and_request_bound(
) -> Result<(), Box<dyn std::error::Error>> {
    let extension = request();
    let digest = extension.digest()?;
    let encoded = serde_json::to_value(&extension)?;
    assert_eq!(encoded["schema"], VERIFIED_OUTCOME_REQUEST_SCHEMA);
    assert!(encoded.get("unknown").is_none());

    let first = intent(extension.clone()).binding_hash()?;
    let mut changed = extension;
    changed.receiver_binding_digest = "9".repeat(64);
    let second = intent(changed).binding_hash()?;

    assert_eq!(digest.len(), 64);
    assert_ne!(first, second);
    Ok(())
}

#[test]
fn verified_outcome_extension_validates_derived_ids_and_schema() {
    let mut invalid = request();
    invalid.pricing_id = "pricing-1".to_owned();
    assert!(invalid.validate().is_err());
    assert!(invalid.digest().is_err());

    let mut invalid = request();
    invalid.predicate_id = "A".repeat(64);
    assert!(invalid.validate().is_err());

    let mut invalid = request();
    invalid.schema = "chio.outcome.request.v9".to_owned();
    assert!(invalid.validate().is_err());
}

#[test]
fn verified_outcome_extension_rejects_unknown_fields() -> Result<(), Box<dyn std::error::Error>> {
    let mut encoded = serde_json::to_value(request())?;
    let Some(object) = encoded.as_object_mut() else {
        return Err("verified outcome request did not serialize as an object".into());
    };
    object.insert("future".to_owned(), serde_json::Value::Bool(true));
    assert!(serde_json::from_value::<VerifiedOutcomeRequestV1>(encoded).is_err());
    Ok(())
}
