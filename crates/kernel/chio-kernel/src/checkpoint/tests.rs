//! Unit tests for Merkle-committed receipt batch checkpointing.
//!
//! Split from `checkpoint.rs` to keep that module inside the production file
//! size limit enforced by `scripts/check-rust-file-hygiene.py`.

use super::*;

fn make_receipt_bytes(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| format!("{{\"receipt_id\":\"rcpt-{i:04}\",\"seq\":{i}}}").into_bytes())
        .collect()
}

fn chain_leaves(checkpoints: &[&KernelCheckpoint]) -> Vec<Hash> {
    checkpoints
        .iter()
        .map(|checkpoint| checkpoint_chain_leaf_hash(&checkpoint.body).expect("chain leaf"))
        .collect()
}

#[test]
fn build_checkpoint_100_has_tree_size_100() {
    let kp = Keypair::generate();
    let batch = make_receipt_bytes(100);
    let cp = build_checkpoint(1, 1, 100, &batch, &kp).expect("build_checkpoint failed");
    assert_eq!(cp.body.tree_size, 100);
}

#[test]
fn build_checkpoint_signature_verifies() {
    let kp = Keypair::generate();
    let batch = make_receipt_bytes(10);
    let cp = build_checkpoint(1, 1, 10, &batch, &kp).expect("build_checkpoint failed");
    assert!(
        verify_checkpoint_signature(&cp).expect("verify failed"),
        "signature should be valid"
    );
}

#[test]
fn build_checkpoint_wrong_key_fails_verification() {
    let kp1 = Keypair::generate();
    let kp2 = Keypair::generate();
    let batch = make_receipt_bytes(5);
    let mut cp = build_checkpoint(1, 1, 5, &batch, &kp1).expect("build_checkpoint failed");
    // Replace the kernel_key with a different key -- signature no longer matches.
    cp.body.kernel_key = kp2.public_key();
    assert!(
        !verify_checkpoint_signature(&cp).expect("verify call failed"),
        "tampered key should fail"
    );
}

#[test]
fn build_checkpoint_single_receipt() {
    let kp = Keypair::generate();
    let batch = make_receipt_bytes(1);
    let cp = build_checkpoint(1, 1, 1, &batch, &kp).expect("build_checkpoint failed");
    assert_eq!(cp.body.tree_size, 1);
    assert!(
        verify_checkpoint_signature(&cp).expect("verify failed"),
        "single-receipt checkpoint should have valid signature"
    );
}

#[test]
fn build_checkpoint_rejects_receipt_count_that_disagrees_with_batch_bounds() {
    let kp = Keypair::generate();
    let error = build_checkpoint(1, 10, 12, &make_receipt_bytes(2), &kp)
        .expect_err("builder must not sign inconsistent batch bounds");

    assert!(
        error
            .to_string()
            .contains("receipt batch length 2 does not match covered entry count 3"),
        "unexpected error: {error}"
    );
}

#[test]
fn build_checkpoint_single_receipt_merkle_root_equals_leaf_hash() {
    // Degenerate case: a single-receipt batch must produce a Merkle root
    // equal to the leaf hash of that receipt's canonical bytes (per RFC 6962:
    // LeafHash(bytes) = SHA256(0x00 || bytes)).
    use chio_core::merkle::leaf_hash;

    let kp = Keypair::generate();
    let leaf_bytes = b"single-receipt-canonical-bytes";
    let batch = vec![leaf_bytes.to_vec()];
    let cp = build_checkpoint(1, 1, 1, &batch, &kp).expect("build_checkpoint failed");

    let expected_root = leaf_hash(leaf_bytes);
    assert_eq!(
        cp.body.merkle_root, expected_root,
        "single-receipt checkpoint merkle_root must equal leaf_hash of the receipt bytes"
    );
    assert_eq!(cp.body.tree_size, 1);
    assert!(
        verify_checkpoint_signature(&cp).expect("verify failed"),
        "single-receipt checkpoint signature should verify"
    );
}

#[test]
fn builder_uses_current_checkpoint_schema() {
    let kp = Keypair::generate();
    let batch = make_receipt_bytes(3);
    let cp = build_checkpoint(1, 1, 3, &batch, &kp).expect("build_checkpoint failed");
    assert_eq!(cp.body.schema, CHECKPOINT_SCHEMA);
    assert!(cp.body.previous_checkpoint_sha256.is_none());
}

#[test]
fn build_checkpoint_with_previous_sets_continuity_hash() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp)
        .expect("first checkpoint build failed");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(&first),
        &chain_leaves(&[&first]),
    )
    .expect("second checkpoint build failed");
    let expected_previous_checkpoint_sha256 =
        checkpoint_body_sha256(&first.body).expect("previous digest");

    assert_eq!(
        second.body.previous_checkpoint_sha256.as_deref(),
        Some(expected_previous_checkpoint_sha256.as_str())
    );
    assert!(
        verify_checkpoint_continuity(&first, &second).expect("continuity verification"),
        "second checkpoint should extend the first"
    );
}

#[test]
fn build_checkpoint_with_chain_frontier_accepts_canonical_successor() -> Result<(), CheckpointError>
{
    let keypair = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &keypair)?;
    let first_leaf = checkpoint_chain_leaf_hash(&first.body)?;
    let frontier = CheckpointChainFrontier::from_leaves(&[first_leaf]);

    let second = build_checkpoint_with_chain_frontier(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &keypair,
        Some(&first),
        &frontier,
    )?;

    validate_checkpoint_predecessor(&first, &second)?;
    assert!(second.body.chain_root.is_some());
    Ok(())
}

#[test]
fn build_checkpoint_with_chain_frontier_rejects_foreign_legacy_predecessor_leaf(
) -> Result<(), CheckpointError> {
    let keypair = Keypair::generate();
    let mut legacy = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &keypair)?;
    legacy.body.schema = CHECKPOINT_SCHEMA_V1.to_string();
    legacy.body.chain_root = None;
    legacy.signature = keypair.sign(&canonical_json_bytes(&legacy.body)?);

    let foreign_frontier = CheckpointChainFrontier::from_leaves(&[Hash::zero()]);
    let result = build_checkpoint_with_chain_frontier(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &keypair,
        Some(&legacy),
        &foreign_frontier,
    );

    assert!(matches!(
        result,
        Err(CheckpointError::Continuity(message))
            if message.contains("legacy predecessor 1 is not the final supplied chain leaf")
    ));
    Ok(())
}

#[test]
fn build_checkpoint_with_chain_frontier_rejects_invalid_predecessor() -> Result<(), CheckpointError>
{
    let keypair = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &keypair)?;
    let first_leaf = checkpoint_chain_leaf_hash(&first.body)?;
    let frontier = CheckpointChainFrontier::from_leaves(&[first_leaf]);

    let mut invalid_signature = first.clone();
    invalid_signature.body.issued_at = invalid_signature.body.issued_at.saturating_add(1);
    let result = build_checkpoint_with_chain_frontier(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &keypair,
        Some(&invalid_signature),
        &frontier,
    );
    assert!(matches!(result, Err(CheckpointError::InvalidSignature)));

    let mut invalid_body = first;
    invalid_body.body.tree_size = invalid_body.body.tree_size.saturating_add(1);
    let result = build_checkpoint_with_chain_frontier(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &keypair,
        Some(&invalid_body),
        &frontier,
    );
    assert!(matches!(
        result,
        Err(CheckpointError::Invalid(message))
            if message.contains("tree_size 4 does not match covered entry count 3")
    ));

    Ok(())
}

#[test]
fn build_checkpoint_with_chain_frontier_rejects_discontinuous_successor(
) -> Result<(), CheckpointError> {
    let keypair = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &keypair)?;
    let first_leaf = checkpoint_chain_leaf_hash(&first.body)?;
    let frontier = CheckpointChainFrontier::from_leaves(&[first_leaf]);

    let result = build_checkpoint_with_chain_frontier(
        3,
        4,
        6,
        &make_receipt_bytes(3),
        &keypair,
        Some(&first),
        &frontier,
    );
    assert!(matches!(
        result,
        Err(CheckpointError::Continuity(message))
            if message.contains("checkpoint_seq 3 does not immediately follow predecessor 1")
    ));

    let result = build_checkpoint_with_chain_frontier(
        2,
        5,
        6,
        &make_receipt_bytes(2),
        &keypair,
        Some(&first),
        &frontier,
    );
    assert!(matches!(
        result,
        Err(CheckpointError::Continuity(message))
            if message.contains(
                "batch_start_seq 5 does not immediately follow predecessor batch_end_seq 3"
            )
    ));

    let result = build_checkpoint_with_chain_frontier(
        2,
        3,
        3,
        &make_receipt_bytes(1),
        &keypair,
        Some(&first),
        &frontier,
    );
    assert!(matches!(
        result,
        Err(CheckpointError::Continuity(message))
            if message.contains(
                "batch_start_seq 3 does not immediately follow predecessor batch_end_seq 3"
            )
    ));

    Ok(())
}

#[test]
fn build_checkpoint_with_chain_frontier_rejects_successor_overflow() -> Result<(), CheckpointError>
{
    let keypair = Keypair::generate();
    let maximum_sequence = build_checkpoint(u64::MAX, 1, 1, &make_receipt_bytes(1), &keypair)?;
    let result = build_checkpoint_with_chain_frontier(
        u64::MAX,
        2,
        2,
        &make_receipt_bytes(1),
        &keypair,
        Some(&maximum_sequence),
        &CheckpointChainFrontier::empty(),
    );
    assert!(matches!(
        result,
        Err(CheckpointError::Continuity(message))
            if message.contains("predecessor checkpoint_seq overflowed u64")
    ));

    let maximum_batch = build_checkpoint(1, u64::MAX, u64::MAX, &make_receipt_bytes(1), &keypair)?;
    let maximum_batch_leaf = checkpoint_chain_leaf_hash(&maximum_batch.body)?;
    let frontier = CheckpointChainFrontier::from_leaves(&[maximum_batch_leaf]);
    let result = build_checkpoint_with_chain_frontier(
        2,
        u64::MAX,
        u64::MAX,
        &make_receipt_bytes(1),
        &keypair,
        Some(&maximum_batch),
        &frontier,
    );
    assert!(matches!(
        result,
        Err(CheckpointError::Continuity(message))
            if message.contains("predecessor batch_end_seq overflowed u64")
    ));

    Ok(())
}

#[test]
fn build_checkpoint_transparency_derives_publications_and_witnesses() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build first");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(&first),
        &chain_leaves(&[&first]),
    )
    .expect("build second");

    let transparency =
        validate_checkpoint_transparency(&[first.clone(), second.clone()]).expect("summary");

    assert_eq!(transparency.publications.len(), 2);
    assert_eq!(transparency.witnesses.len(), 1);
    assert_eq!(transparency.consistency_proofs.len(), 1);
    assert!(transparency.equivocations.is_empty());
    assert_eq!(
        transparency.publications[0].log_id,
        checkpoint_log_id(&first)
    );
    assert_eq!(transparency.publications[0].log_tree_size, 3);
    assert_eq!(transparency.publications[1].entry_start_seq, 4);
    assert_eq!(transparency.publications[1].entry_end_seq, 6);
    assert_eq!(
        transparency.publications[0].checkpoint_sha256,
        checkpoint_body_sha256(&first.body).expect("first digest")
    );
    assert_eq!(transparency.witnesses[0].log_id, checkpoint_log_id(&first));
    assert_eq!(transparency.witnesses[0].checkpoint_seq, 1);
    assert_eq!(transparency.witnesses[0].witness_checkpoint_seq, 2);
    assert_eq!(transparency.consistency_proofs[0].from_log_tree_size, 3);
    assert_eq!(transparency.consistency_proofs[0].to_log_tree_size, 6);
}

#[test]
fn transparency_verifies_each_checkpoint_once_for_a_large_prefix() {
    const CHECKPOINT_COUNT: u64 = 128;

    let keypair = Keypair::generate();
    let mut frontier = CheckpointChainFrontier::empty();
    let mut checkpoints = Vec::<KernelCheckpoint>::with_capacity(CHECKPOINT_COUNT as usize);
    for checkpoint_seq in 1..=CHECKPOINT_COUNT {
        let receipt = format!("receipt-{checkpoint_seq}").into_bytes();
        let checkpoint = build_checkpoint_with_chain_frontier(
            checkpoint_seq,
            checkpoint_seq,
            checkpoint_seq,
            &[receipt],
            &keypair,
            checkpoints.last(),
            &frontier,
        )
        .expect("build checkpoint prefix");
        frontier
            .append(checkpoint_chain_leaf_hash(&checkpoint.body).expect("checkpoint chain leaf"));
        checkpoints.push(checkpoint);
    }

    let verifications_before = checkpoint_signature_verification_count_for_test();
    let inspections_before = checkpoint_equivocation_inspection_count_for_test();
    let transparency =
        validate_checkpoint_transparency(&checkpoints).expect("validate checkpoint prefix");
    let verification_count =
        checkpoint_signature_verification_count_for_test() - verifications_before;
    let inspection_count = checkpoint_equivocation_inspection_count_for_test() - inspections_before;

    assert_eq!(transparency.publications.len(), CHECKPOINT_COUNT as usize);
    assert_eq!(transparency.witnesses.len(), CHECKPOINT_COUNT as usize - 1);
    assert_eq!(
        verification_count, CHECKPOINT_COUNT as usize,
        "transparency validation must verify each checkpoint signature exactly once"
    );
    assert_eq!(
        inspection_count, 0,
        "a clean prefix must not inspect any checkpoint pairs for equivocation"
    );

    let conflicting = build_checkpoint(1, 1, 1, &[b"conflicting-receipt".to_vec()], &keypair)
        .expect("build conflicting checkpoint");
    let inspections_before = checkpoint_equivocation_inspection_count_for_test();
    let conflict_summary = build_checkpoint_transparency(&[checkpoints[0].clone(), conflicting])
        .expect("derive conflicting transparency");
    let inspection_count = checkpoint_equivocation_inspection_count_for_test() - inspections_before;
    assert_eq!(inspection_count, 1, "one indexed pair must be inspected");
    assert_eq!(conflict_summary.equivocations.len(), 1);
    assert_eq!(
        conflict_summary.equivocations[0].kind,
        CheckpointEquivocationKind::ConflictingCheckpointSeq
    );

    let duplicate_checkpoints = vec![checkpoints[0].clone(); CHECKPOINT_COUNT as usize];
    let verifications_before = checkpoint_signature_verification_count_for_test();
    let inspections_before = checkpoint_equivocation_inspection_count_for_test();
    let duplicate_summary = build_checkpoint_transparency(&duplicate_checkpoints)
        .expect("derive duplicate checkpoint transparency");
    let verification_count =
        checkpoint_signature_verification_count_for_test() - verifications_before;
    let inspection_count = checkpoint_equivocation_inspection_count_for_test() - inspections_before;
    assert_eq!(
        duplicate_summary.publications.len(),
        CHECKPOINT_COUNT as usize
    );
    assert!(duplicate_summary.equivocations.is_empty());
    assert_eq!(verification_count, CHECKPOINT_COUNT as usize);
    assert_eq!(
        inspection_count, 0,
        "identical bodies must not create quadratic candidate scans"
    );
}

#[test]
fn validate_checkpoint_transparency_rejects_duplicate_signed_checkpoints() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 2, &make_receipt_bytes(2), &kp).expect("build first");
    let second = build_checkpoint_with_previous(
        2,
        3,
        4,
        &make_receipt_bytes(2),
        &kp,
        Some(&first),
        &chain_leaves(&[&first]),
    )
    .expect("build second");

    let error = validate_checkpoint_transparency(&[first.clone(), first, second])
        .expect_err("duplicate signed checkpoints must fail closed");
    assert!(
        error
            .to_string()
            .contains("duplicate checkpoint sequence 1"),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_checkpoint_transparency_requires_the_first_receipt_prefix() {
    let keypair = Keypair::generate();
    let checkpoint = build_checkpoint(1, 5, 5, &make_receipt_bytes(1), &keypair)
        .expect("build signed late-starting checkpoint");
    validate_checkpoint(&checkpoint).expect("single-checkpoint integrity remains valid");

    let error = validate_checkpoint_transparency(&[checkpoint])
        .expect_err("transparency must reject a prefix that starts after receipt one");
    assert!(
        error
            .to_string()
            .contains("checkpoint 1 must start at receipt 1, got 5"),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_checkpoint_rejects_zero_time_and_malformed_predecessor_digest() {
    let keypair = Keypair::generate();
    let checkpoint = build_checkpoint(1, 1, 1, &make_receipt_bytes(1), &keypair)
        .expect("build signed checkpoint");

    let mut zero_time = checkpoint.clone();
    zero_time.body.issued_at = 0;
    let error = validate_checkpoint(&zero_time).expect_err("zero issued_at must fail closed");
    assert!(error
        .to_string()
        .contains("issued_at must be greater than zero"));

    let mut malformed_predecessor = checkpoint;
    malformed_predecessor.body.previous_checkpoint_sha256 = Some("not-a-digest".to_string());
    let error = validate_checkpoint(&malformed_predecessor)
        .expect_err("malformed predecessor digest must fail closed");
    assert!(error
        .to_string()
        .contains("must be 64 lowercase hex characters"));
}

#[test]
fn checkpoint_body_rejects_explicit_null_options_at_deserialization() {
    let keypair = Keypair::generate();
    let checkpoint = build_checkpoint(1, 1, 1, &make_receipt_bytes(1), &keypair)
        .expect("build signed checkpoint");

    for field in ["previous_checkpoint_sha256", "chain_root"] {
        let mut document =
            serde_json::to_value(&checkpoint).expect("serialize signed checkpoint fixture");
        document["body"][field] = serde_json::Value::Null;
        let error = serde_json::from_value::<KernelCheckpoint>(document)
            .expect_err("explicit null checkpoint options must fail closed");
        assert!(
            error.to_string().contains("explicit null is not permitted"),
            "unexpected {field} error: {error}"
        );
    }
}

#[test]
fn checkpoint_log_id_preserves_historical_ed25519_hashing() {
    let kp = Keypair::generate();
    let checkpoint =
        build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build checkpoint");

    assert_eq!(
        checkpoint_log_id(&checkpoint),
        format!("local-log-{}", sha256_hex(kp.public_key().as_bytes()))
    );
}

#[test]
fn build_trust_anchored_checkpoint_publication_records_binding() {
    let kp = Keypair::generate();
    let checkpoint =
        build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build checkpoint");
    let publication = build_trust_anchored_checkpoint_publication(
        &checkpoint,
        CheckpointPublicationTrustAnchorBinding {
            publication_identity: chio_core::receipt::checkpoint::CheckpointPublicationIdentity::new(
                chio_core::receipt::checkpoint::CheckpointPublicationIdentityKind::TransparencyService,
                "transparency.example/checkpoints/1",
            ),
            trust_anchor_identity: chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentity::new(
                chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentityKind::Did,
                "did:chio:operator-root",
            ),
            trust_anchor_ref: "chio_checkpoint_witness_chain".to_string(),
            signer_cert_ref: "did:web:chio.example#checkpoint-signer".to_string(),
            publication_profile_version: "phase4-preview.v1".to_string(),
        },
    )
    .expect("build trust-anchored publication");

    assert_eq!(
        publication
            .trust_anchor_binding
            .as_ref()
            .expect("binding")
            .trust_anchor_ref,
        "chio_checkpoint_witness_chain"
    );
    assert_eq!(
        publication
            .trust_anchor_binding
            .as_ref()
            .expect("binding")
            .publication_identity
            .identity,
        "transparency.example/checkpoints/1"
    );
    assert_eq!(publication.log_id, checkpoint_log_id(&checkpoint));
}

#[test]
fn verify_checkpoint_transparency_records_rejects_duplicate_publication_coverage() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 2, &make_receipt_bytes(2), &kp).expect("first checkpoint");
    let second = build_checkpoint_with_previous(
        2,
        3,
        4,
        &make_receipt_bytes(2),
        &kp,
        Some(&first),
        &chain_leaves(&[&first]),
    )
    .expect("second checkpoint");
    let derived =
        validate_checkpoint_transparency(&[first.clone(), second.clone()]).expect("transparency");
    let supplied = CheckpointTransparencySummary {
        publications: vec![
            derived.publications[0].clone(),
            derived.publications[0].clone(),
        ],
        witnesses: derived.witnesses.clone(),
        consistency_proofs: derived.consistency_proofs.clone(),
        equivocations: derived.equivocations.clone(),
    };

    let error = verify_checkpoint_transparency_records(&[first, second], &supplied)
        .expect_err("duplicate publication coverage should fail");
    assert!(
        error
            .to_string()
            .contains("duplicate checkpoint publication record"),
        "unexpected error: {error}"
    );
}

#[test]
fn build_trust_anchored_checkpoint_publication_rejects_invalid_binding() {
    let kp = Keypair::generate();
    let checkpoint =
        build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build checkpoint");
    let error = build_trust_anchored_checkpoint_publication(
        &checkpoint,
        CheckpointPublicationTrustAnchorBinding {
            publication_identity: chio_core::receipt::checkpoint::CheckpointPublicationIdentity::new(
                chio_core::receipt::checkpoint::CheckpointPublicationIdentityKind::TransparencyService,
                "",
            ),
            trust_anchor_identity: chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentity::new(
                chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentityKind::Did,
                "did:chio:operator-root",
            ),
            trust_anchor_ref: "chio_checkpoint_witness_chain".to_string(),
            signer_cert_ref: "".to_string(),
            publication_profile_version: "phase4-preview.v1".to_string(),
        },
    )
    .expect_err("blank signer certificate ref must be rejected");
    assert!(error.to_string().contains("publication_identity.identity"));
}

#[test]
fn trust_anchor_binding_validation_precedes_checkpoint_validation() {
    let keypair = Keypair::generate();
    let mut checkpoint =
        build_checkpoint(1, 1, 1, &make_receipt_bytes(1), &keypair).expect("build checkpoint");
    checkpoint.body.issued_at = checkpoint.body.issued_at.saturating_add(1);

    let error = build_trust_anchored_checkpoint_publication(
        &checkpoint,
        CheckpointPublicationTrustAnchorBinding {
            publication_identity:
                chio_core::receipt::checkpoint::CheckpointPublicationIdentity::new(
                    chio_core::receipt::checkpoint::CheckpointPublicationIdentityKind::TransparencyService,
                    "",
                ),
            trust_anchor_identity:
                chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentity::new(
                    chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentityKind::Did,
                    "did:chio:operator-root",
                ),
            trust_anchor_ref: "chio_checkpoint_witness_chain".to_string(),
            signer_cert_ref: "".to_string(),
            publication_profile_version: "phase4-preview.v1".to_string(),
        },
    )
    .expect_err("invalid binding must be rejected before the checkpoint");
    assert!(error.to_string().contains("publication_identity.identity"));
}

#[test]
fn build_trust_anchored_checkpoint_publication_rejects_mismatched_local_log_identity() {
    let kp = Keypair::generate();
    let checkpoint =
        build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build checkpoint");
    let error = build_trust_anchored_checkpoint_publication(
        &checkpoint,
        CheckpointPublicationTrustAnchorBinding {
            publication_identity:
                chio_core::receipt::checkpoint::CheckpointPublicationIdentity::new(
                    chio_core::receipt::checkpoint::CheckpointPublicationIdentityKind::LocalLog,
                    "local-log-not-the-real-one",
                ),
            trust_anchor_identity:
                chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentity::new(
                    chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentityKind::OperatorRoot,
                    "chio-operator-root",
                ),
            trust_anchor_ref: "chio_checkpoint_witness_chain".to_string(),
            signer_cert_ref: "did:web:chio.example#checkpoint-signer".to_string(),
            publication_profile_version: "phase4-preview.v1".to_string(),
        },
    )
    .expect_err("mismatched local log identity must be rejected");
    assert!(error.to_string().contains("does not match log_id"));
}

#[test]
fn detect_checkpoint_equivocation_reports_conflicting_sequence() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"two".to_vec()], &kp)
        .expect("first checkpoint");
    let conflicting = build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"changed".to_vec()], &kp)
        .expect("conflicting checkpoint");

    let equivocation = detect_checkpoint_equivocation(&first, &conflicting)
        .expect("equivocation detection")
        .expect("expected conflict");
    assert_eq!(
        equivocation.kind,
        CheckpointEquivocationKind::ConflictingCheckpointSeq
    );
    assert_eq!(equivocation.first_checkpoint_seq, 1);
    assert_eq!(equivocation.second_checkpoint_seq, 1);
}

fn pairwise_checkpoint_equivocations(
    checkpoints: &[KernelCheckpoint],
) -> Vec<CheckpointEquivocation> {
    let mut equivocations = Vec::new();
    for (position, checkpoint) in checkpoints.iter().enumerate() {
        for conflicting in checkpoints.iter().skip(position + 1) {
            if let Some(equivocation) = detect_checkpoint_equivocation(checkpoint, conflicting)
                .expect("pairwise equivocation detection")
            {
                equivocations.push(equivocation);
            }
        }
    }
    equivocations.sort();
    equivocations.dedup();
    equivocations
}

#[test]
fn indexed_equivocation_matches_pairwise_orientation_and_priority() {
    let keypair = Keypair::generate();
    let with_predecessor = |mut checkpoint: KernelCheckpoint, digest: &str| {
        checkpoint.body.previous_checkpoint_sha256 = Some(digest.repeat(32));
        checkpoint.signature = keypair.sign(
            &canonical_json_bytes(&checkpoint.body).expect("canonical checkpoint with predecessor"),
        );
        checkpoint
    };

    let sequence_first = with_predecessor(
        build_checkpoint(2, 1, 1, &[b"sequence-first".to_vec()], &keypair)
            .expect("build first sequence checkpoint"),
        "11",
    );
    let sequence_second = with_predecessor(
        build_checkpoint(2, 1, 1, &[b"sequence-second".to_vec()], &keypair)
            .expect("build second sequence checkpoint"),
        "22",
    );
    let tree_size_first = build_checkpoint(
        2,
        1,
        2,
        &[b"tree-first-a".to_vec(), b"tree-first-b".to_vec()],
        &keypair,
    )
    .expect("build first tree-size checkpoint");
    let tree_size_second = build_checkpoint(
        3,
        1,
        2,
        &[b"tree-second-a".to_vec(), b"tree-second-b".to_vec()],
        &keypair,
    )
    .expect("build second tree-size checkpoint");
    let predecessor_first = with_predecessor(
        build_checkpoint(2, 1, 1, &[b"predecessor-first".to_vec()], &keypair)
            .expect("build first predecessor checkpoint"),
        "33",
    );
    let predecessor_second = with_predecessor(
        build_checkpoint(3, 2, 2, &[b"predecessor-second".to_vec()], &keypair)
            .expect("build second predecessor checkpoint"),
        "33",
    );
    let overlap_first = with_predecessor(
        build_checkpoint(4, 3, 3, &[b"overlap-first".to_vec()], &keypair)
            .expect("build first overlap checkpoint"),
        "44",
    );
    let overlap_second = with_predecessor(
        build_checkpoint(4, 3, 3, &[b"overlap-second".to_vec()], &keypair)
            .expect("build second overlap checkpoint"),
        "44",
    );

    for (checkpoints, expected_kind) in [
        (
            vec![sequence_first.clone(), sequence_second.clone()],
            CheckpointEquivocationKind::ConflictingCheckpointSeq,
        ),
        (
            vec![tree_size_first, tree_size_second],
            CheckpointEquivocationKind::ConflictingLogTreeSize,
        ),
        (
            vec![predecessor_first, predecessor_second],
            CheckpointEquivocationKind::ConflictingPredecessorWitness,
        ),
        (
            vec![overlap_first, overlap_second],
            CheckpointEquivocationKind::ConflictingCheckpointSeq,
        ),
        (
            vec![
                sequence_first.clone(),
                sequence_second.clone(),
                sequence_first.clone(),
            ],
            CheckpointEquivocationKind::ConflictingCheckpointSeq,
        ),
        (
            vec![sequence_second.clone(), sequence_first, sequence_second],
            CheckpointEquivocationKind::ConflictingCheckpointSeq,
        ),
    ] {
        let expected = pairwise_checkpoint_equivocations(&checkpoints);
        let actual = build_checkpoint_transparency(&checkpoints)
            .expect("indexed transparency")
            .equivocations;
        assert_eq!(actual, expected);
        assert!(actual
            .iter()
            .all(|equivocation| equivocation.kind == expected_kind));
    }
}

#[test]
fn checkpoint_rejects_same_log_same_tree_size_fork() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(&first),
        &chain_leaves(&[&first]),
    )
    .expect("second");
    let fork = build_checkpoint_with_previous(
        9,
        1,
        6,
        &[
            b"fork-one".to_vec(),
            b"fork-two".to_vec(),
            b"fork-three".to_vec(),
            b"fork-four".to_vec(),
            b"fork-five".to_vec(),
            b"fork-six".to_vec(),
        ],
        &kp,
        None,
        &[],
    )
    .expect("fork");

    let error = validate_checkpoint_transparency(&[first, second, fork])
        .expect_err("same-log same-tree-size fork should fail");
    assert!(
        error.to_string().contains("cumulative tree size 6"),
        "unexpected error: {error}"
    );
}

#[test]
fn checkpoint_consistency_proof_verifies_chain_growth() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(&first),
        &chain_leaves(&[&first]),
    )
    .expect("second");
    let third = build_checkpoint_with_previous(
        3,
        7,
        9,
        &make_receipt_bytes(3),
        &kp,
        Some(&second),
        &chain_leaves(&[&first, &second]),
    )
    .expect("third");

    let leaves = chain_leaves(&[&first, &second, &third]);
    let proof = build_checkpoint_consistency_proof(&first, &second, &leaves[..2]).expect("proof");
    assert_eq!(proof.schema, CHECKPOINT_CONSISTENCY_PROOF_SCHEMA);
    assert_eq!(proof.log_id, checkpoint_log_id(&first));
    assert_eq!(proof.from_log_tree_size, 3);
    assert_eq!(proof.to_log_tree_size, 6);
    assert_eq!(proof.appended_entry_start_seq, 4);
    assert_eq!(proof.appended_entry_end_seq, 6);
    assert_eq!(proof.from_chain_root, first.body.chain_root);
    assert_eq!(proof.to_chain_root, second.body.chain_root);
    assert!(
        verify_checkpoint_consistency_proof(&first, &second, &proof).expect("verify proof"),
        "chain-growth proof should verify"
    );

    let later = build_checkpoint_consistency_proof(&second, &third, &leaves).expect("later");
    assert!(
        !later.chain_proof_hashes.is_empty(),
        "a chain extension past one leaf must carry node hashes"
    );
    assert!(
        verify_checkpoint_consistency_proof_with_anchor(
            &second,
            &third,
            &later,
            CheckpointConsistencyAnchor::ChainPrefix(&leaves[..2]),
        )
        .expect("verify later"),
        "second chain-growth proof should verify against the verified prefix"
    );
    assert!(
        verify_checkpoint_consistency_proof_with_anchor(
            &second,
            &third,
            &later,
            CheckpointConsistencyAnchor::VerifiedChainRoot(
                second.body.chain_root.expect("second chain root")
            ),
        )
        .expect("verify later against a pinned root"),
        "a previously verified chain root anchors the same proof"
    );
}

#[test]
fn legacy_v1_consistency_record_deserializes_and_verifies_with_legacy_semantics() {
    let kp = Keypair::generate();
    let mut first =
        build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first checkpoint");
    first.body.schema = CHECKPOINT_SCHEMA_V1.to_string();
    first.body.chain_root = None;
    first.signature =
        kp.sign(&canonical_json_bytes(&first.body).expect("canonical legacy first body"));

    let mut second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(&first),
        &chain_leaves(&[&first]),
    )
    .expect("second checkpoint");
    second.body.schema = CHECKPOINT_SCHEMA_V1.to_string();
    second.body.chain_root = None;
    second.signature =
        kp.sign(&canonical_json_bytes(&second.body).expect("canonical legacy second body"));

    let legacy_json = serde_json::json!({
        "schema": CHECKPOINT_CONSISTENCY_PROOF_SCHEMA_V1,
        "log_id": checkpoint_log_id(&second),
        "from_checkpoint_seq": 1,
        "to_checkpoint_seq": 2,
        "from_checkpoint_sha256": checkpoint_body_sha256(&first.body).expect("first digest"),
        "to_checkpoint_sha256": checkpoint_body_sha256(&second.body).expect("second digest"),
        "from_log_tree_size": 3,
        "to_log_tree_size": 6,
        "appended_entry_start_seq": 4,
        "appended_entry_end_seq": 6
    });
    let proof: CheckpointConsistencyProof =
        serde_json::from_value(legacy_json).expect("legacy proof deserializes");

    assert!(
        verify_checkpoint_consistency_proof(&first, &second, &proof).expect("legacy verification"),
        "an exact legacy metadata record remains verifiable as legacy evidence"
    );
}

#[test]
fn consistency_proof_rejects_maximum_untrusted_leaf_index_without_panicking() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(&first),
        &chain_leaves(&[&first]),
    )
    .expect("second");
    let mut proof =
        build_checkpoint_consistency_proof(&first, &second, &chain_leaves(&[&first, &second]))
            .expect("proof");
    proof
        .from_leaf_inclusion
        .as_mut()
        .expect("earlier leaf inclusion")
        .leaf_index = usize::MAX;

    assert!(
        !verify_checkpoint_consistency_proof(&first, &second, &proof)
            .expect("malformed proof is denied"),
        "an overflowing leaf index must fail closed"
    );
}

#[test]
fn transparency_preserves_post_rotation_consistency_proofs() {
    let first_key = Keypair::generate();
    let rotated_key = Keypair::generate();
    let first =
        build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &first_key).expect("first checkpoint");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &rotated_key,
        Some(&first),
        &chain_leaves(&[&first]),
    )
    .expect("rotated checkpoint");
    let third = build_checkpoint_with_previous(
        3,
        7,
        9,
        &make_receipt_bytes(3),
        &rotated_key,
        Some(&second),
        &chain_leaves(&[&first, &second]),
    )
    .expect("post-rotation checkpoint");

    let transparency =
        build_checkpoint_transparency(&[first, second, third]).expect("transparency");
    assert_eq!(transparency.consistency_proofs.len(), 1);
    assert_eq!(transparency.consistency_proofs[0].from_checkpoint_seq, 2);
    assert_eq!(transparency.consistency_proofs[0].to_checkpoint_seq, 3);
}

#[test]
fn transparency_rejects_divergent_chain_root_at_key_rotation() {
    let first_key = Keypair::generate();
    let rotated_key = Keypair::generate();
    let first =
        build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &first_key).expect("first checkpoint");
    let mut second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &rotated_key,
        Some(&first),
        &chain_leaves(&[&first]),
    )
    .expect("rotated checkpoint");
    second.body.chain_root =
        Some(checkpoint_chain_root(&[leaf_hash(b"unrelated-rotated-history")]).expect("root"));
    second.signature = rotated_key
        .sign(&canonical_json_bytes(&second.body).expect("canonical rotated checkpoint body"));

    let error = build_checkpoint_transparency(&[first, second])
        .expect_err("key rotation must not bypass the global chain commitment");
    assert!(
        error
            .to_string()
            .contains("does not extend the retained checkpoint chain"),
        "unexpected error: {error}"
    );
}

#[test]
fn transparency_derives_legacy_v1_consistency_records() {
    let keypair = Keypair::generate();
    let mut first =
        build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &keypair).expect("first checkpoint");
    first.body.schema = CHECKPOINT_SCHEMA_V1.to_string();
    first.body.chain_root = None;
    first.signature =
        keypair.sign(&canonical_json_bytes(&first.body).expect("canonical first v1 body"));

    let mut second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &keypair,
        Some(&first),
        &chain_leaves(&[&first]),
    )
    .expect("second checkpoint");
    second.body.schema = CHECKPOINT_SCHEMA_V1.to_string();
    second.body.chain_root = None;
    second.body.previous_checkpoint_sha256 =
        Some(checkpoint_body_sha256(&first.body).expect("first v1 digest"));
    second.signature =
        keypair.sign(&canonical_json_bytes(&second.body).expect("canonical second v1 body"));

    let transparency = validate_checkpoint_transparency(&[first.clone(), second.clone()])
        .expect("legacy transparency");
    assert_eq!(transparency.consistency_proofs.len(), 1);
    let proof = &transparency.consistency_proofs[0];
    assert_eq!(proof.schema, CHECKPOINT_CONSISTENCY_PROOF_SCHEMA_V1);
    assert!(verify_checkpoint_consistency_proof(&first, &second, proof)
        .expect("verify legacy metadata record"));
    assert!(
        verify_checkpoint_transparency_records(&[first, second], &transparency).is_ok(),
        "a derived legacy record must round-trip through record verification"
    );
}

#[test]
fn checkpoint_consistency_proof_rejects_unrelated_chain_root() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(&first),
        &chain_leaves(&[&first]),
    )
    .expect("second");
    let leaves = chain_leaves(&[&first, &second]);
    let honest = build_checkpoint_consistency_proof(&first, &second, &leaves).expect("proof");

    // A key-holding log that rewrites history: the successor commits a
    // chain root with no append-only relation to the predecessor's, and
    // re-signs. Every metadata field can be made to match, but the Merkle
    // path cannot.
    let mut rewritten = second.clone();
    rewritten.body.chain_root =
        Some(checkpoint_chain_root(&[leaf_hash(b"rewritten-history")]).expect("root"));
    rewritten.signature = kp
        .sign(&canonical_json_bytes(&rewritten.body).expect("canonical rewritten checkpoint body"));

    let mut forged = honest.clone();
    forged.to_checkpoint_sha256 =
        checkpoint_body_sha256(&rewritten.body).expect("rewritten digest");
    forged.to_chain_root = rewritten.body.chain_root;
    assert!(
        !verify_checkpoint_consistency_proof(&first, &rewritten, &forged).expect("verify forged"),
        "a chain root with no append-only relation must not verify"
    );

    // Tampering any single field of an otherwise honest proof fails too.
    let mut tampered = honest.clone();
    tampered.to_chain_root = Some(Hash::zero());
    assert!(
        !verify_checkpoint_consistency_proof(&first, &second, &tampered).expect("verify tampered"),
        "a tampered to_chain_root must not verify"
    );
    let mut truncated = honest.clone();
    truncated.chain_proof_hashes.push(Hash::zero());
    assert!(
        !verify_checkpoint_consistency_proof(&first, &second, &truncated).expect("verify extended"),
        "an extended proof path must not verify"
    );
}

#[test]
fn checkpoint_consistency_proof_requires_the_committed_chain_to_end_in_this_checkpoint() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(&first),
        &chain_leaves(&[&first]),
    )
    .expect("second");
    let leaves = chain_leaves(&[&first, &second]);
    let honest = build_checkpoint_consistency_proof(&first, &second, &leaves).expect("proof");

    // A key holder commits a chain whose last leaf is not its own body and
    // re-signs. The verifier recomputes from the checkpoint's true leaf, so
    // the substituted root cannot be reproduced.
    let smuggled_leaf = leaf_hash(b"not-this-checkpoint");
    let smuggled_chain =
        MerkleTree::from_hashes(vec![leaves[0], smuggled_leaf]).expect("smuggled chain");
    let mut smuggled = second.clone();
    smuggled.body.chain_root = Some(smuggled_chain.root());
    smuggled.signature =
        kp.sign(&canonical_json_bytes(&smuggled.body).expect("canonical smuggled checkpoint body"));
    let mut smuggled_proof = honest.clone();
    smuggled_proof.to_checkpoint_sha256 =
        checkpoint_body_sha256(&smuggled.body).expect("smuggled digest");
    smuggled_proof.to_chain_root = Some(smuggled_chain.root());
    smuggled_proof.chain_proof_hashes = smuggled_chain.consistency_proof(1).expect("smuggled path");
    smuggled_proof.to_leaf_inclusion = Some(
        smuggled_chain
            .inclusion_proof(1)
            .expect("smuggled inclusion"),
    );
    assert!(
        !verify_checkpoint_consistency_proof(&first, &smuggled, &smuggled_proof)
            .expect("verify smuggled chain"),
        "a chain whose last leaf is not this checkpoint must not verify"
    );

    let mut wrong_index = honest.clone();
    wrong_index
        .to_leaf_inclusion
        .as_mut()
        .expect("later leaf inclusion")
        .leaf_index = 0;
    assert!(
        !verify_checkpoint_consistency_proof(&first, &second, &wrong_index)
            .expect("verify wrong index"),
        "the checkpoint leaf must be proven at the last position"
    );
}

/// A pair starting after checkpoint 1 must bind BOTH endpoints. The forged
/// chain here has correct sizes and a genuine prefix relation, and its
/// later endpoint really does commit the later body, so every other check
/// passes: only binding the earlier leaf catches that checkpoint 2's
/// signed root never contained checkpoint 2.
#[test]
fn checkpoint_consistency_proof_binds_the_earlier_endpoint_too() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(&first),
        &chain_leaves(&[&first]),
    )
    .expect("second");
    let third = build_checkpoint_with_previous(
        3,
        7,
        9,
        &make_receipt_bytes(3),
        &kp,
        Some(&second),
        &chain_leaves(&[&first, &second]),
    )
    .expect("third");
    let honest_leaves = chain_leaves(&[&first, &second, &third]);
    let honest =
        build_checkpoint_consistency_proof(&second, &third, &honest_leaves).expect("honest");

    // Same sizes as the honest chain, but the second leaf is junk instead
    // of checkpoint 2's body; checkpoint 3's real leaf is still appended.
    let forged_from = vec![honest_leaves[0], leaf_hash(b"never-checkpoint-two")];
    let mut forged_to = forged_from.clone();
    forged_to.push(honest_leaves[2]);
    let forged_from_tree = MerkleTree::from_hashes(forged_from).expect("forged from tree");
    let forged_to_tree = MerkleTree::from_hashes(forged_to).expect("forged to tree");

    let mut forged_second = second.clone();
    forged_second.body.chain_root = Some(forged_from_tree.root());
    forged_second.signature =
        kp.sign(&canonical_json_bytes(&forged_second.body).expect("canonical forged second body"));
    let mut forged_third = third.clone();
    forged_third.body.previous_checkpoint_sha256 =
        Some(checkpoint_body_sha256(&forged_second.body).expect("forged second digest"));
    forged_third.body.chain_root = Some(forged_to_tree.root());
    forged_third.signature =
        kp.sign(&canonical_json_bytes(&forged_third.body).expect("canonical forged third body"));

    let forged = CheckpointConsistencyProof {
        from_checkpoint_sha256: checkpoint_body_sha256(&forged_second.body)
            .expect("forged from digest"),
        to_checkpoint_sha256: checkpoint_body_sha256(&forged_third.body).expect("forged to digest"),
        from_chain_root: Some(forged_from_tree.root()),
        to_chain_root: Some(forged_to_tree.root()),
        chain_proof_hashes: forged_to_tree.consistency_proof(2).expect("forged path"),
        from_leaf_inclusion: Some(
            forged_from_tree
                .inclusion_proof(1)
                .expect("forged from leaf"),
        ),
        to_leaf_inclusion: Some(forged_to_tree.inclusion_proof(2).expect("forged to leaf")),
        ..honest
    };

    // The later endpoint and the consistency path are internally valid.
    assert!(
        verify_consistency_proof(
            2,
            3,
            &forged.from_chain_root.expect("forged from root"),
            &forged.to_chain_root.expect("forged to root"),
            &forged.chain_proof_hashes,
        ),
        "the forged chain is genuinely prefix-related, so only leaf binding can catch it"
    );
    // Even handed the forged root as the anchor, the earlier body is not in
    // the tree that root commits.
    assert!(
        !verify_checkpoint_consistency_proof_with_anchor(
            &forged_second,
            &forged_third,
            &forged,
            CheckpointConsistencyAnchor::VerifiedChainRoot(forged_from_tree.root()),
        )
        .expect("verify forged mid-chain pair"),
        "an earlier root that does not commit the earlier body must not verify"
    );
}

/// The mirror of the case above: the forged earlier tree does end in
/// checkpoint 2's real leaf, so both endpoints bind and the consistency path
/// is genuine. Only the leaf below the pair is fabricated, which is invisible
/// to a verifier that never sees checkpoint 1.
#[test]
fn mid_chain_consistency_proof_requires_an_anchored_prefix() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(&first),
        &chain_leaves(&[&first]),
    )
    .expect("second");
    let third = build_checkpoint_with_previous(
        3,
        7,
        9,
        &make_receipt_bytes(3),
        &kp,
        Some(&second),
        &chain_leaves(&[&first, &second]),
    )
    .expect("third");
    let honest_leaves = chain_leaves(&[&first, &second, &third]);
    let honest =
        build_checkpoint_consistency_proof(&second, &third, &honest_leaves).expect("honest");

    // Checkpoint 1's leaf is replaced by junk; checkpoints 2 and 3 keep their
    // real leaves at their own positions.
    let forged_from = vec![leaf_hash(b"never-checkpoint-one"), honest_leaves[1]];
    let mut forged_to = forged_from.clone();
    forged_to.push(honest_leaves[2]);
    let forged_from_tree = MerkleTree::from_hashes(forged_from).expect("forged from tree");
    let forged_to_tree = MerkleTree::from_hashes(forged_to).expect("forged to tree");

    let mut forged_second = second.clone();
    forged_second.body.chain_root = Some(forged_from_tree.root());
    forged_second.signature =
        kp.sign(&canonical_json_bytes(&forged_second.body).expect("canonical forged second body"));
    let mut forged_third = third.clone();
    forged_third.body.previous_checkpoint_sha256 =
        Some(checkpoint_body_sha256(&forged_second.body).expect("forged second digest"));
    forged_third.body.chain_root = Some(forged_to_tree.root());
    forged_third.signature =
        kp.sign(&canonical_json_bytes(&forged_third.body).expect("canonical forged third body"));

    let forged = CheckpointConsistencyProof {
        from_checkpoint_sha256: checkpoint_body_sha256(&forged_second.body)
            .expect("forged from digest"),
        to_checkpoint_sha256: checkpoint_body_sha256(&forged_third.body).expect("forged to digest"),
        from_chain_root: Some(forged_from_tree.root()),
        to_chain_root: Some(forged_to_tree.root()),
        chain_proof_hashes: forged_to_tree.consistency_proof(2).expect("forged path"),
        from_leaf_inclusion: Some(
            forged_from_tree
                .inclusion_proof(1)
                .expect("forged from leaf"),
        ),
        to_leaf_inclusion: Some(forged_to_tree.inclusion_proof(2).expect("forged to leaf")),
        ..honest.clone()
    };

    let error = verify_checkpoint_consistency_proof(&forged_second, &forged_third, &forged)
        .expect_err("a mid-chain pair is not genesis-anchored");
    assert!(
        error.to_string().contains("is unanchored"),
        "unexpected error: {error}"
    );

    assert!(
        !verify_checkpoint_consistency_proof_with_anchor(
            &forged_second,
            &forged_third,
            &forged,
            CheckpointConsistencyAnchor::ChainPrefix(&honest_leaves[..2]),
        )
        .expect("verify forged prefix"),
        "a fabricated pre-pair history must not verify against the real prefix"
    );

    assert!(
        verify_checkpoint_consistency_proof_with_anchor(
            &second,
            &third,
            &honest,
            CheckpointConsistencyAnchor::ChainPrefix(&honest_leaves[..2]),
        )
        .expect("verify honest prefix"),
        "the honest pair still verifies against the real prefix"
    );
}

#[test]
fn checkpoint_consistency_proof_requires_chain_commitment() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(&first),
        &chain_leaves(&[&first]),
    )
    .expect("second");
    let leaves = chain_leaves(&[&first, &second]);
    let proof = build_checkpoint_consistency_proof(&first, &second, &leaves).expect("proof");

    // A legacy pair cannot satisfy a v2 cryptographic proof.
    let mut legacy_first = first.clone();
    legacy_first.body.schema = CHECKPOINT_SCHEMA_V1.to_string();
    legacy_first.body.chain_root = None;
    legacy_first.signature =
        kp.sign(&canonical_json_bytes(&legacy_first.body).expect("canonical legacy first body"));
    let mut legacy_second = second.clone();
    legacy_second.body.schema = CHECKPOINT_SCHEMA_V1.to_string();
    legacy_second.body.previous_checkpoint_sha256 =
        Some(checkpoint_body_sha256(&legacy_first.body).expect("legacy digest"));
    legacy_second.body.chain_root = None;
    legacy_second.signature =
        kp.sign(&canonical_json_bytes(&legacy_second.body).expect("canonical legacy second body"));

    assert!(
        !verify_checkpoint_consistency_proof(&legacy_first, &legacy_second, &proof)
            .expect("legacy pair is denied"),
        "a v2 proof must not verify against legacy checkpoints"
    );
}

#[test]
fn validate_checkpoint_predecessor_rejects_chain_commitment_downgrade() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
    let mut second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(&first),
        &chain_leaves(&[&first]),
    )
    .expect("second");
    second.body.chain_root = None;
    second.signature =
        kp.sign(&canonical_json_bytes(&second.body).expect("canonical downgraded checkpoint body"));

    let error =
        validate_checkpoint_predecessor(&first, &second).expect_err("downgrade should fail");
    assert!(
        error.to_string().contains("drops the chain commitment"),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_checkpoint_predecessor_requires_first_v2_successor_commitment() {
    let kp = Keypair::generate();
    let mut legacy_first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
    legacy_first.body.schema = CHECKPOINT_SCHEMA_V1.to_string();
    legacy_first.body.chain_root = None;
    legacy_first.signature =
        kp.sign(&canonical_json_bytes(&legacy_first.body).expect("canonical legacy body"));

    let mut v2_second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(&legacy_first),
        &chain_leaves(&[&legacy_first]),
    )
    .expect("v2 successor");
    v2_second.body.chain_root = None;
    v2_second.signature =
        kp.sign(&canonical_json_bytes(&v2_second.body).expect("canonical v2 body"));

    let error = validate_checkpoint_predecessor(&legacy_first, &v2_second)
        .expect_err("the first v2 successor must start the retained chain commitment");
    assert!(
        error
            .to_string()
            .contains("does not start or extend the chain commitment"),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_checkpoint_rejects_first_checkpoint_chain_root_mismatch() {
    let kp = Keypair::generate();
    let mut checkpoint =
        build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
    checkpoint.body.chain_root = Some(Hash::zero());
    checkpoint.signature = kp
        .sign(&canonical_json_bytes(&checkpoint.body).expect("canonical tampered checkpoint body"));

    let error = validate_checkpoint(&checkpoint).expect_err("checkpoint should be invalid");
    assert!(
        error
            .to_string()
            .contains("does not commit its own chain leaf"),
        "unexpected error: {error}"
    );
}

#[test]
fn checkpoint_body_rejects_unknown_fields() {
    let kp = Keypair::generate();
    let checkpoint = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
    let mut body_value = serde_json::to_value(&checkpoint.body).expect("serialize checkpoint body");
    body_value["smuggled_field"] = serde_json::json!("payload");

    let error = serde_json::from_value::<KernelCheckpointBody>(body_value)
        .expect_err("unknown body field should be rejected");
    assert!(
        error.to_string().contains("smuggled_field"),
        "unexpected error: {error}"
    );

    let mut checkpoint_value = serde_json::to_value(&checkpoint).expect("serialize checkpoint");
    checkpoint_value["extra"] = serde_json::json!(1);
    let error = serde_json::from_value::<KernelCheckpoint>(checkpoint_value)
        .expect_err("unknown top-level field should be rejected");
    assert!(
        error.to_string().contains("extra"),
        "unexpected error: {error}"
    );
}

#[test]
fn legacy_checkpoint_body_without_chain_root_still_roundtrips() {
    let kp = Keypair::generate();
    let mut checkpoint =
        build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
    checkpoint.body.schema = CHECKPOINT_SCHEMA_V1.to_string();
    checkpoint.body.chain_root = None;
    checkpoint.signature =
        kp.sign(&canonical_json_bytes(&checkpoint.body).expect("canonical legacy checkpoint body"));

    let json = serde_json::to_string(&checkpoint).expect("serialize");
    assert!(
        !json.contains("chain_root"),
        "an absent chain commitment must not appear on the wire"
    );
    let restored: KernelCheckpoint = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restored.body.chain_root, None);
    assert!(
        verify_checkpoint_signature(&restored).expect("verify"),
        "legacy checkpoint signature must survive the roundtrip"
    );
}

#[test]
fn inclusion_proof_verifies_for_leaf_n() {
    let batch = make_receipt_bytes(10);
    let tree = MerkleTree::from_leaves(&batch).expect("tree build failed");
    let root = tree.root();
    let proof = build_inclusion_proof(&tree, 5, 1, 6).expect("proof failed");
    assert!(
        proof.verify(&batch[5], &root),
        "inclusion proof should verify"
    );
}

#[test]
fn inclusion_proof_tampered_bytes_fail() {
    let batch = make_receipt_bytes(10);
    let tree = MerkleTree::from_leaves(&batch).expect("tree build failed");
    let root = tree.root();
    let proof = build_inclusion_proof(&tree, 5, 1, 6).expect("proof failed");
    assert!(
        !proof.verify(b"tampered bytes that are not in the tree", &root),
        "tampered bytes should not verify"
    );
}

#[test]
fn inclusion_proof_all_100_leaves_verify() {
    let batch = make_receipt_bytes(100);
    let tree = MerkleTree::from_leaves(&batch).expect("tree build failed");
    let root = tree.root();
    for (i, leaf) in batch.iter().enumerate().take(100) {
        let proof = build_inclusion_proof(&tree, i, 1, i as u64 + 1).expect("proof failed");
        assert!(proof.verify(leaf, &root), "leaf {i} inclusion proof failed");
    }
}

#[test]
fn checkpoint_body_schema_field() {
    let kp = Keypair::generate();
    let batch = make_receipt_bytes(5);
    let cp = build_checkpoint(7, 101, 105, &batch, &kp).expect("build failed");
    let json = serde_json::to_string(&cp.body).expect("serialize failed");
    assert!(
        json.contains(CHECKPOINT_SCHEMA),
        "JSON should contain schema string"
    );
}

#[test]
fn checkpoint_schema_support_includes_legacy_v1_and_current_v2() {
    assert!(is_supported_checkpoint_schema(CHECKPOINT_SCHEMA_V1));
    assert!(is_supported_checkpoint_schema(CHECKPOINT_SCHEMA_V2));
    assert!(is_supported_checkpoint_schema(CHECKPOINT_SCHEMA));
}

#[test]
fn kernel_checkpoint_serde_roundtrip() {
    let kp = Keypair::generate();
    let batch = make_receipt_bytes(5);
    let cp = build_checkpoint(1, 1, 5, &batch, &kp).expect("build failed");
    let json = serde_json::to_string(&cp).expect("serialize failed");
    let restored: KernelCheckpoint = serde_json::from_str(&json).expect("deserialize failed");
    assert_eq!(cp.body.checkpoint_seq, restored.body.checkpoint_seq);
    assert_eq!(cp.body.tree_size, restored.body.tree_size);
    assert_eq!(cp.signature.to_hex(), restored.signature.to_hex());
    // Verify signature still works after roundtrip.
    assert!(
        verify_checkpoint_signature(&restored).expect("verify failed"),
        "roundtripped checkpoint signature should verify"
    );
}

#[test]
fn validate_checkpoint_rejects_zero_checkpoint_seq() {
    let kp = Keypair::generate();
    let batch = make_receipt_bytes(3);
    let mut checkpoint = build_checkpoint(1, 1, 3, &batch, &kp).expect("build failed");
    checkpoint.body.checkpoint_seq = 0;

    let error = validate_checkpoint(&checkpoint).expect_err("checkpoint should be invalid");
    assert!(
        error
            .to_string()
            .contains("checkpoint_seq must be greater than zero"),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_checkpoint_rejects_tampered_signature() {
    let kp = Keypair::generate();
    let batch = make_receipt_bytes(3);
    let mut checkpoint = build_checkpoint(1, 1, 3, &batch, &kp).expect("build failed");
    checkpoint.body.issued_at = checkpoint.body.issued_at.saturating_add(1);

    let error = validate_checkpoint(&checkpoint).expect_err("checkpoint should be invalid");
    assert!(
        matches!(error, CheckpointError::InvalidSignature),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_checkpoint_rejects_tree_size_that_does_not_match_entry_range() {
    let kp = Keypair::generate();
    let batch = make_receipt_bytes(3);
    let mut checkpoint = build_checkpoint(1, 1, 3, &batch, &kp).expect("build failed");
    checkpoint.body.tree_size = 2;
    checkpoint.signature =
        kp.sign(&canonical_json_bytes(&checkpoint.body).expect("canonical checkpoint body"));

    let error = validate_checkpoint(&checkpoint).expect_err("checkpoint should be invalid");
    assert!(
        error
            .to_string()
            .contains("tree_size 2 does not match covered entry count 3"),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_checkpoint_predecessor_accepts_contiguous_batches() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(&first),
        &chain_leaves(&[&first]),
    )
    .expect("build failed");

    validate_checkpoint_predecessor(&first, &second).expect("continuity should hold");
}

#[test]
fn validate_checkpoint_predecessor_rejects_batch_gap() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
    let mut second = build_checkpoint(2, 5, 6, &make_receipt_bytes(2), &kp).expect("build failed");
    second.body.previous_checkpoint_sha256 =
        Some(checkpoint_body_sha256(&first.body).expect("predecessor digest"));
    second.signature =
        kp.sign(&canonical_json_bytes(&second.body).expect("canonical checkpoint body"));

    let error =
        validate_checkpoint_predecessor(&first, &second).expect_err("continuity should fail");
    assert!(
        error.to_string().contains("does not immediately follow"),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_checkpoint_predecessor_rejects_wrong_predecessor_digest() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
    let mut second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(&first),
        &chain_leaves(&[&first]),
    )
    .expect("build failed");
    second.body.previous_checkpoint_sha256 = Some("00".repeat(32));
    second.signature =
        kp.sign(&canonical_json_bytes(&second.body).expect("canonical second checkpoint body"));

    let error =
        validate_checkpoint_predecessor(&first, &second).expect_err("continuity should fail");
    assert!(
        error
            .to_string()
            .contains("does not match predecessor digest"),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_checkpoint_predecessor_rejects_missing_predecessor_digest() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
    let second = build_checkpoint(2, 4, 6, &make_receipt_bytes(3), &kp).expect("build failed");

    let error =
        validate_checkpoint_predecessor(&first, &second).expect_err("continuity should fail");
    assert!(
        error.to_string().contains("missing predecessor digest"),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_checkpoint_transparency_rejects_predecessor_fork() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"two".to_vec()], &kp)
        .expect("first checkpoint");
    let second = build_checkpoint_with_previous(
        2,
        3,
        4,
        &[b"three".to_vec(), b"four".to_vec()],
        &kp,
        Some(&first),
        &chain_leaves(&[&first]),
    )
    .expect("second checkpoint");
    let mut fork = build_checkpoint_with_previous(
        3,
        5,
        6,
        &[b"five".to_vec(), b"six".to_vec()],
        &kp,
        Some(&second),
        &chain_leaves(&[&first, &second]),
    )
    .expect("fork checkpoint");
    fork.body.previous_checkpoint_sha256 =
        Some(checkpoint_body_sha256(&first.body).expect("first checkpoint digest"));
    fork.signature =
        kp.sign(&canonical_json_bytes(&fork.body).expect("canonical fork checkpoint body"));

    let error = validate_checkpoint_transparency(&[first, second, fork])
        .expect_err("forked checkpoint set should fail");
    assert!(
        error
            .to_string()
            .contains("checkpoint equivocation detected"),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_checkpoint_transparency_rejects_truncated_predecessor_chain() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"two".to_vec()], &kp)
        .expect("first checkpoint");
    let second = build_checkpoint_with_previous(
        2,
        3,
        4,
        &[b"three".to_vec(), b"four".to_vec()],
        &kp,
        Some(&first),
        &chain_leaves(&[&first]),
    )
    .expect("second checkpoint");

    let error = validate_checkpoint_transparency(&[second])
        .expect_err("a checkpoint set with an unresolved predecessor must fail closed");
    assert!(
        error.to_string().contains("unresolved predecessor"),
        "unexpected error: {error}"
    );
}

/// The frontier must agree with a full tree build at every size, otherwise a
/// writer that extends incrementally would sign a different chain commitment
/// than a verifier that rebuilds from leaves.
#[test]
fn chain_frontier_root_matches_a_full_tree_build_at_every_size() {
    let leaves: Vec<Hash> = (0..200u32)
        .map(|i| leaf_hash(format!("chain-leaf-{i}").as_bytes()))
        .collect();

    let mut frontier = CheckpointChainFrontier::empty();
    assert_eq!(frontier.root(), None);
    assert_eq!(frontier.leaf_count(), 0);

    for size in 1..=leaves.len() {
        frontier.append(leaves[size - 1]);
        assert_eq!(frontier.leaf_count(), size as u64, "size {size}");
        assert_eq!(
            frontier.root(),
            Some(checkpoint_chain_root(&leaves[..size]).expect("full build")),
            "frontier root diverges from the full build at size {size}"
        );
        assert_eq!(
            frontier,
            CheckpointChainFrontier::from_leaves(&leaves[..size]),
            "incremental and rebuilt frontiers diverge at size {size}"
        );
    }
}

/// The per-checkpoint path must not rehash the whole chain: the frontier keeps
/// at most one subtree per set bit of the leaf count.
#[test]
fn chain_frontier_stays_logarithmic() {
    let mut frontier = CheckpointChainFrontier::empty();
    for i in 0..4096u32 {
        frontier.append(leaf_hash(format!("chain-leaf-{i}").as_bytes()));
    }
    assert_eq!(frontier.leaf_count(), 4096);
    assert_eq!(
        frontier.subtree_count_for_test(),
        (4096u64).count_ones() as usize,
        "a power-of-two chain collapses to a single perfect subtree"
    );

    frontier.append(leaf_hash(b"one-more"));
    assert_eq!(
        frontier.subtree_count_for_test(),
        (4097u64).count_ones() as usize
    );
}
