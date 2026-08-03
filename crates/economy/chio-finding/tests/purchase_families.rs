//! Behavioral and schema coverage for the purchase families: the unsigned
//! buyer purchase context, the settled purchase record, and the
//! failed-delivery terminal. Cross-artifact resolution (digest agreement,
//! token byte identity, reservation state) belongs to the surfaces that
//! consume these types and is covered there.

use std::error::Error;
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::{canonical_json_bytes, canonical_json_string};
use chio_finding::{
    compute_failed_delivery_id, decode_purchase_context_b64, derive_purchase_key,
    parse_purchase_context, verify_signed_failed_delivery, verify_signed_purchase_record,
    FindingError, FindingFailedDelivery, FindingHoldReleaseTerminal, FindingPurchaseContext,
    FindingPurchaseRecord, FINDING_FAILED_DELIVERY_SCHEMA_V1, FINDING_PURCHASE_RECORD_SCHEMA_V1,
    PURCHASE_CONTEXT_MAX_CANONICAL_BYTES, PURCHASE_CONTEXT_MAX_ENCODED_BYTES,
    PURCHASE_CONTEXT_SCHEMA,
};
use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn Error>>;

const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const HEX64_ALT: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

fn keypair(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn schema_path(family: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-finding/v1")
        .join(format!("{family}.schema.json"))
}

fn validate_family_schema(
    family: &str,
    value: &Value,
) -> Result<(), chio_spec_validate::ValidateError> {
    let path = schema_path(family);
    let schema = chio_spec_validate::load_json(&path)?;
    chio_spec_validate::validate_value(&path, &schema, &path, value)
}

fn assert_family_schema_rejects(family: &str, value: &Value, case: &str) -> TestResult {
    match validate_family_schema(family, value) {
        Err(chio_spec_validate::ValidateError::SchemaViolation(_, _, _)) => Ok(()),
        Err(err) => Err(err.into()),
        Ok(()) => Err(std::io::Error::other(format!(
            "{family} schema accepted invalid case: {case}"
        ))
        .into()),
    }
}

fn canonical_text(value: &Value) -> Result<String, Box<dyn Error>> {
    Ok(canonical_json_string(value)?)
}

fn member(tag: &str) -> Result<String, Box<dyn Error>> {
    canonical_text(&json!({ "member": tag }))
}

fn purchase_context() -> Result<FindingPurchaseContext, Box<dyn Error>> {
    Ok(FindingPurchaseContext {
        schema: PURCHASE_CONTEXT_SCHEMA.to_string(),
        finding_json: canonical_text(&json!({
            "finding_id": HEX64,
            "schema": "chio.finding.v1",
        }))?,
        listing_envelope_json: member("listing")?,
        pricing_hint_envelope_json: member("pricing-hint")?,
        venue_admission_envelope_json: member("venue-admission")?,
        market_terms_envelope_json: member("market-terms")?,
        seller_authorization_envelope_json: member("seller-authorization")?,
        verifier_profile_envelope_json: member("verifier-profile")?,
        seller_backing_envelope_json: member("seller-backing")?,
        verifier_report_envelope_json: member("verifier-report")?,
        bid_request_envelope_json: member("bid-request")?,
        ask_response_envelope_json: member("ask-response")?,
        accepted_bid_envelope_json: member("accepted-bid")?,
        reservation_receipt_envelope_json: member("reservation-receipt")?,
        reservation_store_key: "reservations/finding-listing-01/res-42".to_string(),
        token_offer_json: canonical_text(&json!({
            "scope": format!("finding:{HEX64}"),
            "token_id": "token-42",
        }))?,
    })
}

fn purchase_record_body(buyer: &Keypair, payer: &Keypair) -> FindingPurchaseRecord {
    let accepted_bid_envelope_sha256 = HEX64.to_string();
    let authoritative_payment_operation_id = "payment-operation-42".to_string();
    FindingPurchaseRecord {
        schema: FINDING_PURCHASE_RECORD_SCHEMA_V1.to_string(),
        purchase_key: derive_purchase_key(
            &accepted_bid_envelope_sha256,
            &authoritative_payment_operation_id,
        ),
        purchase_intent_id: "purchase-intent-42".to_string(),
        authoritative_payment_operation_id,
        buyer: buyer.public_key(),
        payer: payer.public_key(),
        finding_id: HEX64.to_string(),
        listing_id: "finding-listing-01".to_string(),
        accepted_bid_envelope_sha256,
        venue_admission_envelope_sha256: HEX64_ALT.to_string(),
        accepted_price: MonetaryAmount {
            units: 450,
            currency: "USD".to_string(),
        },
        realized_spend: MonetaryAmount {
            units: 450,
            currency: "USD".to_string(),
        },
        seller_backing_envelope_sha256: HEX64.to_string(),
        encumbrance_id: "encumbrance-42".to_string(),
        delivery_receipt_id: "delivery-receipt-42".to_string(),
        payment_reference: "rail:venue-ledger:payment-42".to_string(),
        payout_destination: "0x1111111111111111111111111111111111111111".to_owned(),
        recorded_at: 1_750_000_000,
    }
}

fn failed_delivery_body(buyer: &Keypair) -> Result<FindingFailedDelivery, FindingError> {
    let mut failed_delivery = FindingFailedDelivery {
        schema: FINDING_FAILED_DELIVERY_SCHEMA_V1.to_string(),
        failed_delivery_id: String::new(),
        buyer: buyer.public_key(),
        finding_id: HEX64.to_string(),
        listing_id: "finding-listing-01".to_string(),
        accepted_bid_envelope_sha256: HEX64.to_string(),
        reservation_id: "reservation-42".to_string(),
        purchase_intent_id: "purchase-intent-42".to_string(),
        authoritative_payment_operation_id: "payment-operation-42".to_string(),
        hold_attempt_reference: "hold-attempt-42".to_string(),
        release_terminal: FindingHoldReleaseTerminal::Released,
        deny_receipt_id: "deny-receipt-42".to_string(),
        deny_receipt_sha256: HEX64_ALT.to_string(),
        deny_checkpoint_ref: "checkpoints/venue-wedge/9001".to_string(),
        deny_checkpoint_sha256: HEX64.to_string(),
        realized_spend_units: 0,
        currency: "USD".to_string(),
        payout_eligible: false,
        recorded_at: 1_750_000_000,
    };
    failed_delivery.failed_delivery_id = compute_failed_delivery_id(&failed_delivery)?;
    Ok(failed_delivery)
}

#[test]
fn purchase_context_roundtrips_through_canonical_bytes() -> TestResult {
    let context = purchase_context()?;
    (context.validate())?;
    let bytes = canonical_json_bytes(&context)?;
    assert_eq!(parse_purchase_context(&bytes)?, context);
    Ok(())
}

#[test]
fn purchase_context_roundtrips_through_base64() -> TestResult {
    let context = purchase_context()?;
    let bytes = canonical_json_bytes(&context)?;
    let encoded = STANDARD.encode(&bytes);
    assert!(encoded.len() <= PURCHASE_CONTEXT_MAX_ENCODED_BYTES);
    assert_eq!(decode_purchase_context_b64(&encoded)?, context);
    Ok(())
}

#[test]
fn purchase_context_encoded_bound_covers_the_full_raw_bound() {
    let raw = vec![0_u8; PURCHASE_CONTEXT_MAX_CANONICAL_BYTES];
    assert_eq!(
        STANDARD.encode(raw).len(),
        PURCHASE_CONTEXT_MAX_ENCODED_BYTES
    );
}

#[test]
fn purchase_context_rejects_an_oversized_encoding_before_decoding() -> TestResult {
    let encoded = "A".repeat(PURCHASE_CONTEXT_MAX_ENCODED_BYTES + 1);
    assert_eq!(
        decode_purchase_context_b64(&encoded),
        Err(FindingError::SizeLimitExceeded("purchase_context.encoded"))
    );
    assert_eq!(
        decode_purchase_context_b64(""),
        Err(FindingError::SizeLimitExceeded("purchase_context.encoded"))
    );
    Ok(())
}

#[test]
fn purchase_context_rejects_an_oversized_decoded_carrier() -> TestResult {
    let mut context = purchase_context()?;
    context.token_offer_json = canonical_text(&json!({
        "pad": "x".repeat(PURCHASE_CONTEXT_MAX_CANONICAL_BYTES),
    }))?;
    let bytes = canonical_json_bytes(&context)?;
    assert!(bytes.len() > PURCHASE_CONTEXT_MAX_CANONICAL_BYTES);
    assert_eq!(
        parse_purchase_context(&bytes),
        Err(FindingError::SizeLimitExceeded("purchase_context"))
    );
    assert_eq!(
        parse_purchase_context(b""),
        Err(FindingError::SizeLimitExceeded("purchase_context"))
    );
    Ok(())
}

#[test]
fn purchase_context_rejects_non_canonical_carrier_bytes() -> TestResult {
    let context = purchase_context()?;
    let value: Value = serde_json::to_value(&context)?;
    let pretty = serde_json::to_vec_pretty(&value)?;
    assert_eq!(
        parse_purchase_context(&pretty),
        Err(FindingError::NonCanonicalBytes("purchase_context"))
    );
    Ok(())
}

#[test]
fn purchase_context_rejects_an_unknown_member() -> TestResult {
    let context = purchase_context()?;
    let mut value: Value = serde_json::to_value(&context)?;
    value["surprise"] = json!(true);
    let bytes = canonical_json_bytes(&value)?;
    assert_eq!(
        parse_purchase_context(&bytes),
        Err(FindingError::InvalidField("purchase_context"))
    );
    Ok(())
}

#[test]
fn purchase_context_rejects_a_non_canonical_carried_member() -> TestResult {
    let mut context = purchase_context()?;
    context.finding_json = "{ \"schema\" : \"chio.finding.v1\" }".to_string();
    let bytes = canonical_json_bytes(&context)?;
    assert_eq!(
        parse_purchase_context(&bytes),
        Err(FindingError::NonCanonicalBytes("finding_json"))
    );

    let mut context = purchase_context()?;
    context.ask_response_envelope_json = String::new();
    assert_eq!(
        context.validate(),
        Err(FindingError::EmptyField("ask_response_envelope_json"))
    );

    let mut context = purchase_context()?;
    context.reservation_store_key = "  ".to_string();
    assert_eq!(
        context.validate(),
        Err(FindingError::EmptyField("reservation_store_key"))
    );
    Ok(())
}

#[test]
fn purchase_context_rejects_a_foreign_schema() -> TestResult {
    let mut context = purchase_context()?;
    context.schema = "chio.finding.purchase-context.v9".to_string();
    assert!(matches!(
        context.validate(),
        Err(FindingError::UnsupportedSchema(_))
    ));
    Ok(())
}

#[test]
fn purchase_context_conforms_to_its_schema() -> TestResult {
    let context = purchase_context()?;
    let value: Value = serde_json::to_value(&context)?;
    validate_family_schema("purchase-context", &value)?;

    let mut unknown = value.clone();
    unknown["surprise"] = json!(true);
    assert_family_schema_rejects("purchase-context", &unknown, "unknown member")?;

    let mut wrong_schema = value.clone();
    wrong_schema["schema"] = json!("chio.finding.purchase-context.v9");
    assert_family_schema_rejects("purchase-context", &wrong_schema, "wrong schema const")?;

    let mut empty_member = value;
    empty_member["token_offer_json"] = json!("");
    assert_family_schema_rejects("purchase-context", &empty_member, "empty member")?;
    Ok(())
}

#[test]
fn purchase_key_derivation_is_stable_and_pair_specific() -> TestResult {
    let first = derive_purchase_key(HEX64, "payment-operation-42");
    assert_eq!(first, derive_purchase_key(HEX64, "payment-operation-42"));
    assert_eq!(first.len(), 64);
    assert_ne!(first, derive_purchase_key(HEX64, "payment-operation-43"));
    assert_ne!(
        first,
        derive_purchase_key(HEX64_ALT, "payment-operation-42")
    );
    // The NUL separator keeps the two members from sliding into each other.
    assert_ne!(
        derive_purchase_key("ab", "cd"),
        derive_purchase_key("a", "bcd")
    );
    Ok(())
}

#[test]
fn purchase_record_validates_and_detects_tampering() -> TestResult {
    let buyer = keypair(21);
    let payer = keypair(22);
    let record = purchase_record_body(&buyer, &payer);
    (record.validate())?;

    let mut tampered = purchase_record_body(&buyer, &payer);
    tampered.accepted_bid_envelope_sha256 = HEX64_ALT.to_string();
    assert_eq!(
        tampered.validate(),
        Err(FindingError::ArtifactIdMismatch("purchase_key"))
    );

    let mut tampered = purchase_record_body(&buyer, &payer);
    tampered.authoritative_payment_operation_id = "payment-operation-43".to_string();
    assert_eq!(
        tampered.validate(),
        Err(FindingError::ArtifactIdMismatch("purchase_key"))
    );
    Ok(())
}

#[test]
fn purchase_record_rejects_currency_mismatch_and_overcapture() -> TestResult {
    let buyer = keypair(21);
    let payer = keypair(22);

    let mut record = purchase_record_body(&buyer, &payer);
    record.realized_spend.currency = "EUR".to_string();
    assert_eq!(
        record.validate(),
        Err(FindingError::CurrencyMismatch("purchase_record"))
    );

    let mut record = purchase_record_body(&buyer, &payer);
    record.realized_spend.units = record.accepted_price.units + 1;
    assert_eq!(
        record.validate(),
        Err(FindingError::InvalidField("realized_spend"))
    );

    let mut record = purchase_record_body(&buyer, &payer);
    record.realized_spend.units = record.accepted_price.units - 1;
    (record.validate())?;
    Ok(())
}

#[test]
fn purchase_record_rejects_unbounded_identifiers() -> TestResult {
    let buyer = keypair(21);
    let payer = keypair(22);
    let mut record = purchase_record_body(&buyer, &payer);
    record.payout_destination = "r".repeat(chio_finding::MAX_FINDING_IDENTIFIER_BYTES + 1);
    assert_eq!(
        record.validate(),
        Err(FindingError::SizeLimitExceeded("payout_destination"))
    );
    Ok(())
}

#[test]
fn purchase_record_rejects_a_seller_controlled_harm_destination() {
    let buyer = keypair(21);
    let payer = keypair(22);
    let mut record = purchase_record_body(&buyer, &payer);
    record.payout_destination = "rail:venue-ledger:seller-42".to_owned();
    assert_eq!(
        record.validate(),
        Err(FindingError::InvalidField("payout_destination"))
    );
}

#[test]
fn purchase_record_signs_and_verifies_under_its_pinned_authority() -> TestResult {
    let buyer = keypair(21);
    let payer = keypair(22);
    let authority = keypair(16);
    let interloper = keypair(9);

    let signed = SignedExportEnvelope::sign(purchase_record_body(&buyer, &payer), &authority)?;
    (verify_signed_purchase_record(&signed, &authority.public_key()))?;
    assert_eq!(
        verify_signed_purchase_record(&signed, &interloper.public_key()),
        Err(FindingError::AuthorityMismatch("purchase_record"))
    );

    let forged = SignedExportEnvelope::sign(purchase_record_body(&buyer, &payer), &interloper)?;
    assert_eq!(
        verify_signed_purchase_record(&forged, &authority.public_key()),
        Err(FindingError::AuthorityMismatch("purchase_record"))
    );
    Ok(())
}

#[test]
fn purchase_record_conforms_to_its_schema() -> TestResult {
    let buyer = keypair(21);
    let payer = keypair(22);
    let authority = keypair(16);
    let signed = SignedExportEnvelope::sign(purchase_record_body(&buyer, &payer), &authority)?;
    let value: Value = serde_json::to_value(&signed)?;
    validate_family_schema("purchase-record", &value)?;

    let mut unknown = value.clone();
    unknown["surprise"] = json!(true);
    assert_family_schema_rejects("purchase-record", &unknown, "unknown member")?;

    let mut wrong_schema = value.clone();
    wrong_schema["body"]["schema"] = json!("chio.finding.purchase-record.v9");
    assert_family_schema_rejects("purchase-record", &wrong_schema, "wrong schema const")?;

    let mut zero_price = value;
    zero_price["body"]["accepted_price"]["units"] = json!(0);
    assert_family_schema_rejects("purchase-record", &zero_price, "zero accepted price")?;
    Ok(())
}

#[test]
fn failed_delivery_content_address_is_stable_and_detects_tampering() -> TestResult {
    let buyer = keypair(23);
    let failed_delivery = failed_delivery_body(&buyer)?;
    (failed_delivery.validate())?;
    assert_eq!(
        compute_failed_delivery_id(&failed_delivery)?,
        failed_delivery.failed_delivery_id
    );

    let mut tampered = failed_delivery_body(&buyer)?;
    tampered.release_terminal = FindingHoldReleaseTerminal::CancelledBeforeAuthorization;
    assert_eq!(
        tampered.validate(),
        Err(FindingError::ArtifactIdMismatch("failed_delivery_id"))
    );

    let mut tampered = failed_delivery_body(&buyer)?;
    tampered.deny_checkpoint_ref = "checkpoints/venue-wedge/9002".to_string();
    assert_eq!(
        tampered.validate(),
        Err(FindingError::ArtifactIdMismatch("failed_delivery_id"))
    );
    Ok(())
}

#[test]
fn failed_delivery_rejects_realized_spend_and_payout_eligibility() -> TestResult {
    let buyer = keypair(23);

    let mut failed_delivery = failed_delivery_body(&buyer)?;
    failed_delivery.realized_spend_units = 1;
    failed_delivery.failed_delivery_id = compute_failed_delivery_id(&failed_delivery)?;
    assert_eq!(
        failed_delivery.validate(),
        Err(FindingError::InvalidField("realized_spend_units"))
    );

    let mut failed_delivery = failed_delivery_body(&buyer)?;
    failed_delivery.payout_eligible = true;
    failed_delivery.failed_delivery_id = compute_failed_delivery_id(&failed_delivery)?;
    assert_eq!(
        failed_delivery.validate(),
        Err(FindingError::InvalidField("payout_eligible"))
    );
    Ok(())
}

#[test]
fn failed_delivery_signs_and_verifies_under_its_pinned_authority() -> TestResult {
    let buyer = keypair(23);
    let authority = keypair(17);
    let interloper = keypair(9);

    let signed = SignedExportEnvelope::sign(failed_delivery_body(&buyer)?, &authority)?;
    (verify_signed_failed_delivery(&signed, &authority.public_key()))?;
    assert_eq!(
        verify_signed_failed_delivery(&signed, &interloper.public_key()),
        Err(FindingError::AuthorityMismatch("failed_delivery"))
    );

    let forged = SignedExportEnvelope::sign(failed_delivery_body(&buyer)?, &interloper)?;
    assert_eq!(
        verify_signed_failed_delivery(&forged, &authority.public_key()),
        Err(FindingError::AuthorityMismatch("failed_delivery"))
    );
    Ok(())
}

#[test]
fn failed_delivery_conforms_to_its_schema() -> TestResult {
    let buyer = keypair(23);
    let authority = keypair(17);
    let signed = SignedExportEnvelope::sign(failed_delivery_body(&buyer)?, &authority)?;
    let value: Value = serde_json::to_value(&signed)?;
    validate_family_schema("failed-delivery", &value)?;

    let mut unknown = value.clone();
    unknown["body"]["surprise"] = json!(true);
    assert_family_schema_rejects("failed-delivery", &unknown, "unknown body member")?;

    let mut wrong_schema = value.clone();
    wrong_schema["body"]["schema"] = json!("chio.finding.failed-delivery.v9");
    assert_family_schema_rejects("failed-delivery", &wrong_schema, "wrong schema const")?;

    let mut spent = value.clone();
    spent["body"]["realized_spend_units"] = json!(1);
    assert_family_schema_rejects("failed-delivery", &spent, "nonzero realized spend")?;

    let mut payable = value.clone();
    payable["body"]["payout_eligible"] = json!(true);
    assert_family_schema_rejects("failed-delivery", &payable, "payout eligible")?;

    let mut unknown_terminal = value;
    unknown_terminal["body"]["release_terminal"] = json!("refunded");
    assert_family_schema_rejects("failed-delivery", &unknown_terminal, "unknown terminal")?;
    Ok(())
}
