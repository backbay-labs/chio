use super::*;

fn sample_v2_primary_proof() -> AnchorInclusionProof {
    let sample = sample_primary_proof();
    let checkpoint_key = chio_core::Keypair::generate();
    let mut receipt_body = sample.receipt.body().clone();
    receipt_body.kernel_key = checkpoint_key.public_key();
    let receipt =
        chio_core::receipt::body::ChioReceipt::sign(receipt_body, &checkpoint_key).test_unwrap();
    let certificate = chio_core::web3::identity::Web3IdentityBindingCertificate {
        schema: chio_core::web3::identity::CHIO_KEY_BINDING_CERTIFICATE_SCHEMA.to_string(),
        chio_identity: format!("did:chio:{}", checkpoint_key.public_key().to_hex()),
        chio_public_key: checkpoint_key.public_key(),
        chain_scope: vec!["eip155:8453".to_string()],
        purpose: vec![chio_core::web3::identity::Web3KeyBindingPurpose::Anchor],
        settlement_address: "0x1000000000000000000000000000000000000002".to_string(),
        issued_at: 1_743_600_000,
        expires_at: 1_774_828_800,
        nonce: "v2-bundle-binding".to_string(),
    };
    let binding = chio_core::web3::identity::SignedWeb3IdentityBinding {
        signature: checkpoint_key.sign_canonical(&certificate).test_unwrap().0,
        certificate,
    };
    let receipt_bytes = chio_core::canonical_json_bytes(&receipt.body()).test_unwrap();
    let checkpoint = build_checkpoint(
        1,
        1,
        1,
        std::slice::from_ref(&receipt_bytes),
        &checkpoint_key,
    )
    .test_unwrap();
    let tree = chio_core::merkle::MerkleTree::from_leaves(std::slice::from_ref(&receipt_bytes))
        .test_unwrap();
    let inclusion = build_inclusion_proof(&tree, 0, 1, 1).test_unwrap();
    let chain_anchor = chio_core::web3::anchors::Web3ChainAnchorRecord {
        chain_id: "eip155:8453".to_string(),
        contract_address: "0x1000000000000000000000000000000000000001".to_string(),
        operator_address: "0x1000000000000000000000000000000000000002".to_string(),
        tx_hash: format!("0x{}", "a1".repeat(32)),
        block_number: 21_000_000,
        block_hash: format!("0x{}", "b2".repeat(32)),
        operator_key_hash: crate::operator_key_hash_hex(&binding).test_unwrap(),
        operator_epoch: 1,
        anchored_merkle_root: checkpoint.body.merkle_root,
        anchored_checkpoint_seq: checkpoint.body.checkpoint_seq,
    };

    build_anchor_inclusion_proof(
        receipt,
        &inclusion,
        &checkpoint,
        Some(chain_anchor),
        binding,
    )
    .test_unwrap()
}

/// A kernel-signed checkpoint must still verify after crossing the web3
/// statement bridge. `Web3CheckpointStatementBody` reconstructs the bytes
/// the kernel signed, so any signed field the bridge drops (the chain
/// commitment did) makes real checkpoints unverifiable while fixtures that
/// sign the reconstruction stay green.
#[test]
fn kernel_signed_checkpoint_survives_the_web3_statement_bridge() {
    let keypair = chio_core::Keypair::generate();
    let checkpoint = chio_kernel::checkpoint::build_checkpoint(
        1,
        1,
        2,
        &[b"receipt-one".to_vec(), b"receipt-two".to_vec()],
        &keypair,
    )
    .test_unwrap();
    assert!(
        checkpoint.body.chain_root.is_some(),
        "the first checkpoint of a chain carries a chain commitment"
    );

    let statement = checkpoint_statement_from_kernel(&checkpoint);
    assert_eq!(statement.chain_root, checkpoint.body.chain_root);
    chio_core::web3::anchors::verify_checkpoint_statement(&statement)
        .test_expect("statement signature verifies across the bridge");

    let restored = kernel_checkpoint_from_statement(&statement);
    assert_eq!(restored, checkpoint, "the bridge round-trips losslessly");
}

#[test]
fn proof_bundle_schema_tracks_the_primary_proof_version() {
    let proof = sample_v2_primary_proof();
    let checkpoint = kernel_checkpoint_from_statement(&proof.checkpoint_statement);
    let prepared = prepare_solana_memo_publication(
        &checkpoint,
        "solana:mainnet-beta",
        "7xKXtg2CW9Q4hN7kD6A6tVWyQGm9Xxq6u9rY2T6yQkZp",
    )
    .test_unwrap();
    let solana = SolanaMemoAnchorRecord::from_prepared(
        &prepared,
        "5W8D7gF9w3mP2nL6e1c4k7T9y2V6a1b3s5d7f9g2h4j6k8m1n3p5q7r9t1u3v5w7".to_string(),
        310_045_221,
        1_743_600_000,
    );
    let mut bundle = AnchorProofBundle {
        schema: CHIO_ANCHOR_PROOF_BUNDLE_SCHEMA_V2.to_string(),
        primary_proof: proof,
        secondary_lanes: vec![AnchorLaneKind::SolanaMemo],
        solana_anchor: Some(solana),
        note: None,
    };

    let mut schema_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    schema_path.push("../../../spec/schemas/chio-web3/v2/anchor-proof-bundle.schema.json");
    let schema_path = std::fs::canonicalize(&schema_path).test_unwrap();
    let schema = chio_spec_validate::load_json(&schema_path).test_unwrap();
    let serialized = serde_json::to_value(&bundle).test_unwrap();
    chio_spec_validate::validate_value(
        &schema_path,
        &schema,
        std::path::Path::new("<sample-anchor-proof-bundle>"),
        &serialized,
    )
    .test_expect("serialized v2 proof bundle satisfies its published schema");

    assert!(verify_proof_bundle(&bundle).test_unwrap().verified);

    bundle.schema = CHIO_ANCHOR_PROOF_BUNDLE_SCHEMA_V1.to_string();
    let error = verify_proof_bundle(&bundle).test_unwrap_err();
    assert!(error.to_string().contains(
        "bundle schema chio.anchor-proof-bundle.v1 requires primary proof schema chio.anchor-inclusion-proof.v1"
    ));
}

/// The report states the EVM primary lane is verified, so the on-chain anchor
/// record that claim rests on has to be there and has to check out.
#[test]
fn v2_proof_bundle_requires_evm_anchor_evidence_for_the_primary_lane() {
    let proof = sample_v2_primary_proof();
    let checkpoint = kernel_checkpoint_from_statement(&proof.checkpoint_statement);
    let prepared = prepare_solana_memo_publication(
        &checkpoint,
        "solana:mainnet-beta",
        "7xKXtg2CW9Q4hN7kD6A6tVWyQGm9Xxq6u9rY2T6yQkZp",
    )
    .test_unwrap();
    let solana = SolanaMemoAnchorRecord::from_prepared(
        &prepared,
        "5W8D7gF9w3mP2nL6e1c4k7T9y2V6a1b3s5d7f9g2h4j6k8m1n3p5q7r9t1u3v5w7".to_string(),
        310_045_221,
        1_743_600_000,
    );
    let mut bundle = AnchorProofBundle {
        schema: CHIO_ANCHOR_PROOF_BUNDLE_SCHEMA_V2.to_string(),
        primary_proof: proof,
        secondary_lanes: vec![AnchorLaneKind::SolanaMemo],
        solana_anchor: Some(solana),
        note: None,
    };

    let report = verify_proof_bundle(&bundle).test_unwrap();
    assert!(report
        .lanes
        .iter()
        .any(|lane| lane.lane == AnchorLaneKind::EvmPrimary && lane.verified));

    let mut anchored = bundle.primary_proof.clone();
    bundle.primary_proof.chain_anchor = None;
    let mut schema_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    schema_path.push("../../../spec/schemas/chio-web3/v2/anchor-proof-bundle.schema.json");
    let schema_path = std::fs::canonicalize(&schema_path).test_unwrap();
    let schema = chio_spec_validate::load_json(&schema_path).test_unwrap();
    let serialized = serde_json::to_value(&bundle).test_unwrap();
    assert!(
        chio_spec_validate::validate_value(
            &schema_path,
            &schema,
            std::path::Path::new("<unanchored-v2-proof-bundle>"),
            &serialized,
        )
        .is_err(),
        "published v2 bundle schema accepted a missing primary chain anchor"
    );
    let error = verify_proof_bundle(&bundle).test_unwrap_err();
    assert!(
        error.to_string().contains(
            "v2 proof bundle must carry primary_proof.chain_anchor for the EVM primary lane"
        ),
        "{error}"
    );

    // A present but unbound anchor record fails the same lane rather than
    // riding through on presence alone.
    anchored
        .chain_anchor
        .as_mut()
        .test_unwrap()
        .anchored_checkpoint_seq += 1;
    bundle.primary_proof = anchored;
    let error = verify_proof_bundle(&bundle).test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("chain anchor checkpoint seq must match checkpoint statement"),
        "{error}"
    );
}

#[test]
fn unsuffixed_proof_bundle_schema_tracks_current_v2_issuance() {
    assert_eq!(
        crate::CHIO_ANCHOR_PROOF_BUNDLE_SCHEMA,
        CHIO_ANCHOR_PROOF_BUNDLE_SCHEMA_V2
    );
}
