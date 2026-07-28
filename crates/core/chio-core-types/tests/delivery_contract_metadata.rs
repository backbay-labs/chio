//! Contract tests for the `chio.delivery-contract.v1` receipt-metadata block.
//!
//! These anchor four properties ADR-0018 item 7 requires:
//!
//! 1. A serialized [`DeliveryContract`] validates against the registered
//!    wire schema (the instance-conformance test the admission block lacks).
//! 2. The schema rejects malformed instances (unknown field, wrong schema
//!    const, non-canonical digest, unknown result token).
//! 3. Mutating a signed receipt's `metadata` breaks `verify_signature`,
//!    because the block is authenticated only by the enclosing receipt.
//! 4. The block survives receipt canonicalization / serde round-trip and is
//!    read back through the typed accessor.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{fs, path::PathBuf};

use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::{Decision, ToolCallAction},
    kinds::TrustLevel,
    metadata::{DeliveryContract, DeliveryResult},
};
use chio_core_types::{DELIVERY_CONTRACT_METADATA_KEY, DELIVERY_CONTRACT_SCHEMA};
use serde_json::{json, Value};

fn expected_digest() -> String {
    sha256_hex(b"expected-delivery-payload")
}

fn observed_digest() -> String {
    sha256_hex(b"observed-delivery-payload")
}

fn matched_contract() -> DeliveryContract {
    let digest = expected_digest();
    DeliveryContract {
        schema: DELIVERY_CONTRACT_SCHEMA.to_string(),
        expected_digest: digest.clone(),
        observed_digest: digest,
        result: DeliveryResult::Matched,
    }
}

fn mismatched_contract() -> DeliveryContract {
    DeliveryContract {
        schema: DELIVERY_CONTRACT_SCHEMA.to_string(),
        expected_digest: expected_digest(),
        observed_digest: observed_digest(),
        result: DeliveryResult::Mismatched,
    }
}

fn metadata_with(contract: &DeliveryContract) -> Value {
    let mut map = serde_json::Map::new();
    map.insert(
        DELIVERY_CONTRACT_METADATA_KEY.to_string(),
        serde_json::to_value(contract).expect("contract serializes"),
    );
    Value::Object(map)
}

fn delivery_schema() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-wire/v1/receipt/delivery-contract.schema.json");
    serde_json::from_str(&fs::read_to_string(&path).expect("delivery-contract schema file exists"))
        .expect("delivery-contract schema parses as json")
}

fn action() -> ToolCallAction {
    ToolCallAction::from_parameters(json!({ "path": "/app/out.json" })).unwrap()
}

fn signed_receipt_with_metadata(kp: &Keypair, metadata: Option<Value>) -> ChioReceipt {
    let body = ChioReceiptBody {
        id: "rcpt-delivery-contract".to_string(),
        timestamp: 1_710_000_000,
        capability_id: "cap-delivery".to_string(),
        tool_server: "srv-delivery".to_string(),
        tool_name: "produce".to_string(),
        action: action(),
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: expected_digest(),
        policy_hash: sha256_hex(b"policy"),
        evidence: Vec::new(),
        metadata,
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: kp.public_key(),
        bbs_projection_version: None,
    };
    ChioReceipt::sign(body, kp).expect("receipt signs")
}

// 1. Instance-conformance: a serialized valid block validates against the schema.

#[test]
fn valid_delivery_contract_matches_registered_schema() {
    let schema = delivery_schema();
    let validator = jsonschema::validator_for(&schema).expect("delivery-contract schema compiles");

    for contract in [matched_contract(), mismatched_contract()] {
        let instance = serde_json::to_value(&contract).expect("contract serializes");
        if let Err(error) = validator.validate(&instance) {
            panic!(
                "registered schema rejected a valid delivery contract:\ninstance={}\nerror={error}",
                serde_json::to_string_pretty(&instance).unwrap()
            );
        }
    }
}

#[test]
fn valid_delivery_contract_passes_typed_validation() {
    matched_contract()
        .validate()
        .expect("matched contract validates");
    mismatched_contract()
        .validate()
        .expect("mismatched contract validates");
}

// 2. Rejection cases against the registered schema.

#[test]
fn schema_rejects_malformed_delivery_contracts() {
    let schema = delivery_schema();
    let validator = jsonschema::validator_for(&schema).expect("delivery-contract schema compiles");
    let digest_owned = expected_digest();
    let digest = digest_owned.as_str();

    let unknown_field = json!({
        "schema": DELIVERY_CONTRACT_SCHEMA,
        "expected_digest": digest,
        "observed_digest": digest,
        "result": "matched",
        "attacker_note": "extra",
    });
    let wrong_schema = json!({
        "schema": "chio.delivery-contract.v9",
        "expected_digest": digest,
        "observed_digest": digest,
        "result": "matched",
    });
    let uppercase_digest = json!({
        "schema": DELIVERY_CONTRACT_SCHEMA,
        "expected_digest": digest.to_uppercase(),
        "observed_digest": digest,
        "result": "matched",
    });
    let short_digest = json!({
        "schema": DELIVERY_CONTRACT_SCHEMA,
        "expected_digest": "abc123",
        "observed_digest": digest,
        "result": "matched",
    });
    let unknown_result = json!({
        "schema": DELIVERY_CONTRACT_SCHEMA,
        "expected_digest": digest,
        "observed_digest": digest,
        "result": "partial",
    });
    let missing_field = json!({
        "schema": DELIVERY_CONTRACT_SCHEMA,
        "expected_digest": digest,
        "result": "matched",
    });

    for (name, instance) in [
        ("unknown field", unknown_field),
        ("wrong schema const", wrong_schema),
        ("uppercase digest", uppercase_digest),
        ("short digest", short_digest),
        ("unknown result token", unknown_result),
        ("missing field", missing_field),
    ] {
        assert!(
            !validator.is_valid(&instance),
            "schema should reject {name}: {}",
            serde_json::to_string(&instance).unwrap()
        );
    }
}

#[test]
fn typed_validation_rejects_bad_schema_and_digests() {
    let mut wrong_schema = matched_contract();
    wrong_schema.schema = "chio.delivery-contract.v9".to_string();
    assert!(wrong_schema.validate().is_err());

    let mut uppercase = matched_contract();
    uppercase.observed_digest = uppercase.observed_digest.to_uppercase();
    assert!(uppercase.validate().is_err());

    let mut short = matched_contract();
    short.expected_digest = "abc123".to_string();
    assert!(short.validate().is_err());
}

#[test]
fn deny_unknown_fields_is_enforced_on_deserialization() {
    let digest_owned = expected_digest();
    let digest = digest_owned.as_str();
    let with_unknown = json!({
        "schema": DELIVERY_CONTRACT_SCHEMA,
        "expected_digest": digest,
        "observed_digest": digest,
        "result": "matched",
        "attacker_note": "extra",
    });
    assert!(serde_json::from_value::<DeliveryContract>(with_unknown).is_err());
}

// 3. Authenticity: mutating receipt metadata breaks verify_signature.

#[test]
fn mutating_delivery_contract_metadata_breaks_verify_signature() {
    let kp = Keypair::generate();
    let receipt = signed_receipt_with_metadata(&kp, Some(metadata_with(&matched_contract())));
    assert!(
        receipt.verify_signature().unwrap(),
        "freshly signed receipt must verify"
    );

    let mut tampered = receipt.clone();
    let block = tampered
        .metadata
        .as_mut()
        .and_then(|value| value.get_mut(DELIVERY_CONTRACT_METADATA_KEY))
        .expect("delivery_contract block present");
    // Flip the recorded result: a downstream forgery attempt.
    block["result"] = json!("mismatched");

    assert!(
        !matches!(tampered.verify_signature(), Ok(true)),
        "tampering with the delivery_contract block must invalidate the receipt signature"
    );
}

#[test]
fn removing_delivery_contract_metadata_breaks_verify_signature() {
    let kp = Keypair::generate();
    let receipt = signed_receipt_with_metadata(&kp, Some(metadata_with(&matched_contract())));

    let mut tampered = receipt.clone();
    if let Some(Value::Object(map)) = tampered.metadata.as_mut() {
        map.remove(DELIVERY_CONTRACT_METADATA_KEY);
    }
    assert!(
        !matches!(tampered.verify_signature(), Ok(true)),
        "stripping the delivery_contract block must invalidate the receipt signature"
    );
}

// 4. Round-trip: the block survives canonicalization and the typed accessor.

#[test]
fn delivery_contract_survives_receipt_round_trip() {
    let kp = Keypair::generate();
    let receipt = signed_receipt_with_metadata(&kp, Some(metadata_with(&mismatched_contract())));

    let read_back = receipt
        .delivery_contract()
        .expect("accessor returns the block on the signed receipt");
    assert_eq!(read_back, mismatched_contract());
    read_back.validate().expect("read-back block validates");

    let wire = serde_json::to_string(&receipt).expect("receipt serializes");
    let restored: ChioReceipt = serde_json::from_str(&wire).expect("receipt deserializes");
    assert!(
        restored.verify_signature().unwrap(),
        "signature must still verify after a serde round-trip"
    );
    assert_eq!(
        restored
            .delivery_contract()
            .expect("accessor after round-trip"),
        mismatched_contract(),
        "delivery_contract block must survive canonicalization byte-for-byte"
    );
}

#[test]
fn accessor_absent_without_the_block() {
    let kp = Keypair::generate();
    let receipt = signed_receipt_with_metadata(&kp, None);
    assert!(receipt.delivery_contract().is_none());
    assert!(receipt.verify_signature().unwrap());
}
