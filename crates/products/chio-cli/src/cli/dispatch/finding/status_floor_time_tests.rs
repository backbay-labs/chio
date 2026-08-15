#[test]
fn status_floor_rejects_rollback_and_same_epoch_equivocation() {
    let dir = tempfile::tempdir().unwrap();
    let floor_path = dir.path().join("status-floor.json");
    let authorization = chio_finding::FindingStatusOperatorAuthorization {
        role: chio_finding::FindingStatusOperatorRole::FindingStatusOperator,
        feed_id: "status-feed/venue-01".to_owned(),
        operator: chio_finding::FindingAuthorityKeyPolicy {
            authority_id: "venue-01-status-operator".to_owned(),
            key: Keypair::from_seed(&[91_u8; 32]).public_key(),
            key_epoch: 4,
            valid_from: 1_700_000_000,
            valid_until: 1_900_000_000,
            rotation_policy_ref: "governance/status-rotation".to_owned(),
            revocation_status_ref: "governance/status-revocation".to_owned(),
        },
        revoked_from: None,
    };
    let authorization_sha256 = sha256_hex(&canonical_json_bytes(&authorization).unwrap());
    let response = FindingStatusProofResponse {
        feed_id: authorization.feed_id.clone(),
        key_domain_nonce: 3_318_287_169_837_494,
        map_epoch: 8,
        epoch_id: "1".repeat(64),
        root_hash: "2".repeat(64),
        finding_id: GOLDEN_FINDING_ID.to_owned(),
        proof_kind: "non_inclusion".to_owned(),
        proof_sha256: "3".repeat(64),
        proof_input_b64: String::new(),
        signed_epoch_sha256: "4".repeat(64),
        signed_epoch_b64: String::new(),
        service_bond_evidence_sha256: "9".repeat(64),
        checked_at: 1_800_000_000,
        valid_until: 1_800_000_300,
    };
    advance_status_floor(
        &floor_path,
        &response,
        &authorization,
        &authorization_sha256,
        1_800_000_000,
    )
    .unwrap();
    assert!(status_floor::require_trusted_time(&floor_path, 1_799_999_999)
        .unwrap_err()
        .to_string()
        .contains("host clock rolled back"));

    let mut rollback = response;
    rollback.map_epoch = 7;
    assert!(advance_status_floor(
        &floor_path,
        &rollback,
        &authorization,
        &authorization_sha256,
        1_800_000_000,
    )
    .unwrap_err()
    .to_string()
    .contains("rollback floor"));

    rollback.map_epoch = 8;
    rollback.root_hash = "5".repeat(64);
    assert!(advance_status_floor(
        &floor_path,
        &rollback,
        &authorization,
        &authorization_sha256,
        1_800_000_000,
    )
    .unwrap_err()
    .to_string()
    .contains("equivocates"));
}
