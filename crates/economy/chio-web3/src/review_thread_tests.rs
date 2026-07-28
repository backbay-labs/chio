use crate::anchors::validate_checkpoint_statement_shape;
use crate::error::Web3ContractError;
use crate::settlement::validate_web3_settlement_dispatch;
use crate::settlement_proof::{
    public_settlement_witness_body_hash, verify_public_settlement_proof,
    PublicSettlementWitnessMode,
};
use serde_json::json;
use std::path::PathBuf;

use super::tests::{
    resign_dispatch_capital_instruction, sample_anchor_inclusion_proof,
    sample_beneficiary_binding_for_address, sample_dispatch,
    sample_public_settlement_proof_bundle_with_chain_snapshot,
    sample_public_settlement_verifier_trust, sign_sample_public_settlement_bundle,
    verify_sample_public_settlement_proof,
};

#[test]
fn web3_checkpoint_statement_rejects_zero_sequences() {
    let mut proof = sample_anchor_inclusion_proof();
    proof.checkpoint_statement.checkpoint_seq = 0;
    assert!(matches!(
        validate_checkpoint_statement_shape(&proof.checkpoint_statement),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("checkpoint_seq must be greater than zero")
    ));

    let mut proof = sample_anchor_inclusion_proof();
    proof.checkpoint_statement.batch_start_seq = 0;
    proof.checkpoint_statement.batch_end_seq = 0;
    assert!(matches!(
        validate_checkpoint_statement_shape(&proof.checkpoint_statement),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("batch_start_seq must be greater than zero")
    ));

    let mut proof = sample_anchor_inclusion_proof();
    proof.checkpoint_statement.issued_at = 0;
    assert!(matches!(
        validate_checkpoint_statement_shape(&proof.checkpoint_statement),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("issued_at must be greater than zero")
    ));

    let mut proof = sample_anchor_inclusion_proof();
    proof.checkpoint_statement.previous_checkpoint_sha256 = Some("not-a-digest".to_string());
    assert!(matches!(
        validate_checkpoint_statement_shape(&proof.checkpoint_statement),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("must be 64 lowercase hex characters")
    ));
}

#[test]
fn web3_checkpoint_statement_rejects_explicit_null_options_at_deserialization() {
    for field in ["previous_checkpoint_sha256", "chain_root"] {
        let mut document = serde_json::to_value(sample_anchor_inclusion_proof())
            .unwrap_or_else(|error| panic!("serialize sample anchor inclusion proof: {error}"));
        document["checkpoint_statement"][field] = serde_json::Value::Null;
        let error = serde_json::from_value::<crate::anchors::AnchorInclusionProof>(document)
            .expect_err("explicit null checkpoint options must fail closed");
        assert!(
            error.to_string().contains("explicit null is not permitted"),
            "unexpected {field} error: {error}"
        );
    }
}

#[test]
fn serialized_anchor_inclusion_proof_satisfies_the_published_schema() {
    let mut schema_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    schema_path.push("../../../spec/schemas/chio-web3/v2/anchor-inclusion-proof.schema.json");
    let schema_path = std::fs::canonicalize(&schema_path)
        .unwrap_or_else(|error| panic!("canonicalize {}: {error}", schema_path.display()));
    let schema = chio_spec_validate::load_json(&schema_path)
        .unwrap_or_else(|error| panic!("load anchor inclusion schema: {error}"));
    let document = serde_json::to_value(sample_anchor_inclusion_proof())
        .unwrap_or_else(|error| panic!("serialize sample anchor inclusion proof: {error}"));

    chio_spec_validate::validate_value(
        &schema_path,
        &schema,
        std::path::Path::new("<sample-anchor-inclusion-proof>"),
        &document,
    )
    .unwrap_or_else(|error| panic!("sample anchor inclusion proof must satisfy schema: {error}"));

    let mut zero_epoch = document.clone();
    zero_epoch["chain_anchor"]["operator_epoch"] = json!(0);
    assert!(
        chio_spec_validate::validate_value(
            &schema_path,
            &schema,
            std::path::Path::new("<zero-operator-epoch>"),
            &zero_epoch,
        )
        .is_err(),
        "published schema must reject a zero operator epoch"
    );

    let mut zero_operator_key_hash = document.clone();
    zero_operator_key_hash["chain_anchor"]["operator_key_hash"] =
        json!(format!("0x{}", "0".repeat(64)));
    assert!(
        chio_spec_validate::validate_value(
            &schema_path,
            &schema,
            std::path::Path::new("<zero-operator-key-hash>"),
            &zero_operator_key_hash,
        )
        .is_err(),
        "published schema must reject a zero operator key hash"
    );

    let mut bitcoin_without_super_root = document;
    bitcoin_without_super_root["bitcoin_anchor"] = json!({
        "method": "opentimestamps",
        "ots_proof_b64": "AA==",
        "bitcoin_block_height": 1,
        "bitcoin_block_hash": "00"
    });
    assert!(
        chio_spec_validate::validate_value(
            &schema_path,
            &schema,
            std::path::Path::new("<bitcoin-without-super-root>"),
            &bitcoin_without_super_root,
        )
        .is_err(),
        "published schema must require super-root metadata for a Bitcoin anchor"
    );

    let mut unsupported_bitcoin_method = bitcoin_without_super_root;
    unsupported_bitcoin_method["super_root_inclusion"] = json!({
        "super_root": format!("0x{}", "1".repeat(64)),
        "proof": {
            "tree_size": 1,
            "leaf_index": 0,
            "audit_path": []
        },
        "aggregated_checkpoint_start": 1042,
        "aggregated_checkpoint_end": 1042
    });
    unsupported_bitcoin_method["bitcoin_anchor"]["method"] = json!("not-opentimestamps");
    assert!(
        chio_spec_validate::validate_value(
            &schema_path,
            &schema,
            std::path::Path::new("<unsupported-bitcoin-method>"),
            &unsupported_bitcoin_method,
        )
        .is_err(),
        "published schema must reject unsupported Bitcoin anchor methods"
    );
}

#[test]
fn published_v2_anchor_schemas_require_canonical_signed_checkpoint_hashes() {
    let mut schema_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    schema_path.push("../../../spec/schemas/chio-web3/v2/anchor-inclusion-proof.schema.json");
    let schema_path = std::fs::canonicalize(&schema_path)
        .unwrap_or_else(|error| panic!("canonicalize {}: {error}", schema_path.display()));
    let schema = chio_spec_validate::load_json(&schema_path)
        .unwrap_or_else(|error| panic!("load anchor inclusion schema: {error}"));
    let mut canonical = serde_json::to_value(sample_anchor_inclusion_proof())
        .unwrap_or_else(|error| panic!("serialize sample anchor inclusion proof: {error}"));
    canonical["checkpoint_statement"]["chain_root"] = json!(format!("0x{}", "3".repeat(64)));

    chio_spec_validate::validate_value(
        &schema_path,
        &schema,
        std::path::Path::new("<canonical-checkpoint-hashes>"),
        &canonical,
    )
    .unwrap_or_else(|error| panic!("canonical checkpoint hashes must satisfy schema: {error}"));

    for (field, value) in [
        ("merkle_root", json!("2".repeat(64))),
        ("merkle_root", json!(format!("0x{}", "A".repeat(64)))),
        ("chain_root", json!("3".repeat(64))),
        ("chain_root", json!(format!("0x{}", "B".repeat(64)))),
    ] {
        let mut noncanonical = canonical.clone();
        noncanonical["checkpoint_statement"][field] = value;
        assert!(
            chio_spec_validate::validate_value(
                &schema_path,
                &schema,
                std::path::Path::new("<noncanonical-checkpoint-hash>"),
                &noncanonical,
            )
            .is_err(),
            "published schema must reject noncanonical checkpoint {field}"
        );
    }

    let mut bundle_schema_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    bundle_schema_path.push("../../../spec/schemas/chio-web3/v2/anchor-proof-bundle.schema.json");
    let bundle_schema_path = std::fs::canonicalize(&bundle_schema_path)
        .unwrap_or_else(|error| panic!("canonicalize {}: {error}", bundle_schema_path.display()));
    let bundle_schema = chio_spec_validate::load_json(&bundle_schema_path)
        .unwrap_or_else(|error| panic!("load anchor proof bundle schema: {error}"));
    let bundle = json!({
        "schema": "chio.anchor-proof-bundle.v2",
        "primary_proof": canonical,
        "secondary_lanes": ["solana_memo"],
        "solana_anchor": {
            "chain_id": "solana:mainnet",
            "operator_pubkey": "operator",
            "memo_program_id": "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
            "tx_signature": "signature",
            "slot": 1,
            "block_time": 1,
            "memo_data": "checkpoint-anchor",
            "anchored_merkle_root": format!("0x{}", "2".repeat(64)),
            "anchored_checkpoint_seq": 1
        }
    });
    chio_spec_validate::validate_value(
        &bundle_schema_path,
        &bundle_schema,
        std::path::Path::new("<canonical-checkpoint-bundle>"),
        &bundle,
    )
    .unwrap_or_else(|error| panic!("canonical checkpoint bundle must satisfy schema: {error}"));

    let mut noncanonical_bundle = bundle;
    noncanonical_bundle["primary_proof"]["checkpoint_statement"]["chain_root"] =
        json!("3".repeat(64));
    assert!(
        chio_spec_validate::validate_value(
            &bundle_schema_path,
            &bundle_schema,
            std::path::Path::new("<noncanonical-checkpoint-bundle>"),
            &noncanonical_bundle,
        )
        .is_err(),
        "bundle schema must inherit canonical checkpoint hash requirements"
    );
}

#[test]
fn web3_dispatch_rejects_beneficiary_outside_signed_rail() {
    let mut dispatch = sample_dispatch();
    dispatch.beneficiary_address = "0x3333333333333333333333333333333333333333".to_string();
    assert!(matches!(
        validate_web3_settlement_dispatch(&dispatch),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("beneficiary_address must match")
    ));

    dispatch = sample_dispatch();
    dispatch
        .capital_instruction
        .body
        .rail
        .destination_account_ref = None;
    resign_dispatch_capital_instruction(&mut dispatch);
    assert!(matches!(
        validate_web3_settlement_dispatch(&dispatch),
        Err(Web3ContractError::MissingField(
            "web3_settlement_dispatch.capital_instruction.rail.destination_account_ref"
        ))
    ));
}

#[test]
fn web3_dispatch_accepts_equivalent_mixed_case_signed_rail_beneficiary() {
    let mut dispatch = sample_dispatch();
    dispatch.beneficiary_address = "0x1234567890ABCDEF1234567890ABCDEF12345678".to_string();
    dispatch
        .capital_instruction
        .body
        .rail
        .destination_account_ref = Some("0x1234567890abcdef1234567890abcdef12345678".to_string());
    resign_dispatch_capital_instruction(&mut dispatch);

    assert!(validate_web3_settlement_dispatch(&dispatch).is_ok());
}

#[test]
fn web3_dispatch_rejects_equal_malformed_evm_beneficiary_refs() {
    let mut dispatch = sample_dispatch();
    dispatch.beneficiary_address = "not-an-address".to_string();
    dispatch
        .capital_instruction
        .body
        .rail
        .destination_account_ref = Some("not-an-address".to_string());
    resign_dispatch_capital_instruction(&mut dispatch);

    assert!(matches!(
        validate_web3_settlement_dispatch(&dispatch),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("EVM address fields must be 0x-prefixed 20-byte hex values")
    ));
}

#[test]
fn public_settlement_proof_rejects_settlement_tx_after_anchor_block_without_release_event() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["chain_snapshot"]["block"]["transaction_hashes"] =
            json!(["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]);
    });
    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement release tx hash missing from block evidence")
    ));
}

#[test]
fn public_settlement_proof_rejects_anchor_tx_not_included_in_block() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["chain_snapshot"]["block"]["transaction_hashes"] =
            json!(["0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"]);
    });
    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement anchor tx hash missing from block")
    ));
}

#[test]
fn public_settlement_proof_accepts_equivalent_mixed_case_evm_addresses() {
    let mut bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["deployment_provenance"]["root_registry_address"] =
            json!("0x1234567890ABCDEF1234567890ABCDEF12345678");
        bundle["deployment_provenance"]["escrow_contract"] =
            json!("0x2234567890ABCDEF1234567890ABCDEF12345678");
        bundle["deployment_provenance"]["bond_vault_contract"] =
            json!("0x3234567890ABCDEF1234567890ABCDEF12345678");
        bundle["settlement_receipt"]["dispatch"]["escrow_contract"] =
            json!("0x2234567890abcdef1234567890abcdef12345678");
        bundle["settlement_receipt"]["dispatch"]["bond_vault_contract"] =
            json!("0x3234567890abcdef1234567890abcdef12345678");
        bundle["settlement_receipt"]["reconciled_anchor_proof"]["chain_anchor"]
            ["contract_address"] = json!("0x1234567890abcdef1234567890abcdef12345678");
        bundle["chain_snapshot"]["root_registry_address"] =
            json!("0x1234567890abcdef1234567890abcdef12345678");
        bundle["chain_snapshot"]["escrow"]["escrow_contract"] =
            json!("0x2234567890ABCDEF1234567890ABCDEF12345678");
        bundle["chain_snapshot"]["bond"]["bond_vault_contract"] =
            json!("0x3234567890ABCDEF1234567890ABCDEF12345678");
    });
    bundle.settlement_receipt.dispatch.beneficiary_address =
        "0x4234567890ABCDEF1234567890ABCDEF12345678".to_string();
    bundle
        .settlement_receipt
        .dispatch
        .capital_instruction
        .body
        .rail
        .destination_account_ref = Some("0x4234567890abcdef1234567890abcdef12345678".to_string());
    resign_dispatch_capital_instruction(&mut bundle.settlement_receipt.dispatch);
    bundle.order_binding.beneficiary_address =
        "0x4234567890abcdef1234567890abcdef12345678".to_string();
    bundle.chain_snapshot.escrow.beneficiary_address =
        "0x4234567890abcdef1234567890abcdef12345678".to_string();
    bundle.chain_snapshot.beneficiary_identity_binding = Some(
        sample_beneficiary_binding_for_address("0x4234567890abcdef1234567890abcdef12345678"),
    );
    let witness = bundle
        .public_witness
        .as_mut()
        .expect("sample bundle has witness");
    witness.root_registry_address = "0x1234567890ABCDEF1234567890ABCDEF12345678".to_string();
    witness.escrow_contract = "0x2234567890abcdef1234567890abcdef12345678".to_string();
    witness.bond_vault_contract = "0x3234567890ABCDEF1234567890ABCDEF12345678".to_string();
    witness.body_hash =
        public_settlement_witness_body_hash(witness).expect("sample witness body hashes");

    assert!(verify_sample_public_settlement_proof(&bundle).is_ok());
}

#[test]
fn public_settlement_proof_rejects_different_evm_addresses_after_normalization() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["chain_snapshot"]["escrow"]["escrow_contract"] =
            json!("0x1000000000000000000000000000000000000004");
    });

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement escrow contract mismatch")
    ));
}

#[test]
fn public_settlement_proof_rejects_future_dated_dispute_snapshot() {
    let bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|bundle| {
        bundle["dispute_snapshot"]["window_closed_at"] = json!(1_743_294_000_u64);
        bundle["dispute_snapshot"]["observed_at"] = json!(1_743_294_001_u64);
    });

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement dispute snapshot is from the future")
    ));
}

#[test]
fn public_settlement_proof_requires_verifier_time_for_live_dispute_snapshot() {
    let mut bundle = sample_public_settlement_proof_bundle_with_chain_snapshot(|_| {});
    let witness = bundle
        .public_witness
        .as_mut()
        .expect("sample public settlement witness exists");
    witness.mode = PublicSettlementWitnessMode::Live;
    witness.body_hash = public_settlement_witness_body_hash(witness).unwrap();
    sign_sample_public_settlement_bundle(&mut bundle);
    let mut trust = sample_public_settlement_verifier_trust();
    trust.verifier_now_unix_seconds = None;

    assert!(matches!(
        verify_public_settlement_proof(&bundle, &trust),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement dispute verifier time missing")
    ));
}
