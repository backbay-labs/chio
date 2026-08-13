use super::*;
use super::super::status_floor::FindingStatusCliFloorV1;

fn authorization() -> chio_finding::FindingStatusOperatorAuthorization {
    chio_finding::FindingStatusOperatorAuthorization {
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
    }
}

fn response(proof_kind: &str) -> FindingStatusProofResponse {
    FindingStatusProofResponse {
        feed_id: "status-feed/venue-01".to_owned(),
        key_domain_nonce: 3_318_287_169_837_494,
        map_epoch: 8,
        epoch_id: "1".repeat(64),
        root_hash: "2".repeat(64),
        finding_id: GOLDEN_FINDING_ID.to_owned(),
        proof_kind: proof_kind.to_owned(),
        proof_sha256: "3".repeat(64),
        proof_input_b64: String::new(),
        signed_epoch_sha256: "4".repeat(64),
        signed_epoch_b64: String::new(),
        service_bond_evidence_sha256: "9".repeat(64),
        checked_at: 1_800_000_000,
        valid_until: 1_800_000_300,
    }
}

fn advance(path: &Path, status: &FindingStatusProofResponse) -> Result<(), CliError> {
    let authorization = authorization();
    let digest = sha256_hex(&canonical_json_bytes(&authorization)?);
    advance_status_floor(path, &status.floor_observation(), &authorization, &digest)
}

#[test]
fn status_floor_rejects_rollback_and_same_epoch_equivocation() {
    let dir = tempfile::tempdir().unwrap();
    let floor_path = dir.path().join("status-floor.json");
    advance(&floor_path, &response("non_inclusion")).unwrap();

    let mut rollback = response("non_inclusion");
    rollback.map_epoch = 7;
    assert!(advance(&floor_path, &rollback)
        .unwrap_err()
        .to_string()
        .contains("rollback floor"));

    rollback.map_epoch = 8;
    rollback.root_hash = "5".repeat(64);
    assert!(advance(&floor_path, &rollback)
        .unwrap_err()
        .to_string()
        .contains("equivocates"));
}

#[test]
fn status_floor_accepts_same_key_authorization_refresh_and_rejects_key_equivocation() {
    let dir = tempfile::tempdir().unwrap();
    let floor_path = dir.path().join("status-floor.json");
    let mut authorization = authorization();
    let mut status = response("non_inclusion");
    let initial_sha256 = sha256_hex(&canonical_json_bytes(&authorization).unwrap());
    advance_status_floor(
        &floor_path,
        &status.floor_observation(),
        &authorization,
        &initial_sha256,
    )
    .unwrap();

    authorization.operator.valid_until = 1_950_000_000;
    let refreshed_sha256 = sha256_hex(&canonical_json_bytes(&authorization).unwrap());
    assert!(advance_status_floor(
        &floor_path,
        &status.floor_observation(),
        &authorization,
        &refreshed_sha256,
    )
    .unwrap_err()
    .to_string()
    .contains("did not advance"));
    status.map_epoch = 9;
    status.epoch_id = "5".repeat(64);
    status.root_hash = "6".repeat(64);
    advance_status_floor(
        &floor_path,
        &status.floor_observation(),
        &authorization,
        &refreshed_sha256,
    )
    .unwrap();
    let floor = read_status_floor(&floor_path).unwrap().unwrap();
    assert_eq!(floor.operator_key, Some(authorization.operator.key.clone()));
    assert_eq!(floor.operator_authorization_sha256, refreshed_sha256);

    authorization.operator.key = Keypair::from_seed(&[92_u8; 32]).public_key();
    let substituted_sha256 = sha256_hex(&canonical_json_bytes(&authorization).unwrap());
    status.map_epoch = 10;
    assert!(advance_status_floor(
        &floor_path,
        &status.floor_observation(),
        &authorization,
        &substituted_sha256,
    )
    .unwrap_err()
    .to_string()
    .contains("key equivocated"));
}

#[test]
fn status_floor_keeps_retractions_sticky_per_finding() {
    let dir = tempfile::tempdir().unwrap();
    let floor_path = dir.path().join("status-floor.json");
    advance(&floor_path, &response("inclusion")).unwrap();

    let mut attempted_revival = response("non_inclusion");
    attempted_revival.map_epoch = 9;
    attempted_revival.epoch_id = "5".repeat(64);
    attempted_revival.root_hash = "6".repeat(64);
    let error = advance(&floor_path, &attempted_revival)
        .unwrap_err()
        .to_string();
    assert!(error.contains("durably retracted"), "unexpected error: {error}");
}

#[test]
fn status_floor_migrates_v1_epoch_and_sticky_retractions() {
    let dir = tempfile::tempdir().unwrap();
    let floor_path = dir.path().join("status-floor.json");
    let authorization = authorization();
    let authorization_sha256 = sha256_hex(&canonical_json_bytes(&authorization).unwrap());
    let legacy = FindingStatusCliFloorV1 {
        schema: "chio.finding.status-cli-floor.v1".to_owned(),
        feed_id: authorization.feed_id.clone(),
        operator_id: authorization.operator.authority_id.clone(),
        rotation_policy_ref: authorization.operator.rotation_policy_ref.clone(),
        operator_key_epoch: authorization.operator.key_epoch,
        operator_key: Some(authorization.operator.key.clone()),
        operator_authorization_sha256: authorization_sha256.clone(),
        key_domain_nonce: 3_318_287_169_837_494,
        map_epoch: 8,
        epoch_id: "1".repeat(64),
        root_hash: "2".repeat(64),
        retracted_finding_ids: std::iter::once(GOLDEN_FINDING_ID.to_owned()).collect(),
    };
    std::fs::write(&floor_path, canonical_json_bytes(&legacy).unwrap()).unwrap();

    let mut status = response("non_inclusion");
    status.map_epoch = 9;
    status.epoch_id = "3".repeat(64);
    status.root_hash = "4".repeat(64);
    status.finding_id = "f".repeat(64);
    advance_status_floor(
        &floor_path,
        &status.floor_observation(),
        &authorization,
        &authorization_sha256,
    )
    .unwrap();

    let migrated = read_status_floor(&floor_path).unwrap().unwrap();
    assert_eq!(migrated.schema, "chio.finding.status-cli-floor.v2");
    assert_eq!(migrated.map_epoch, 9);
    assert_eq!(
        std::fs::read_dir(dir.path().join("status-floor.json.retractions"))
            .unwrap()
            .count(),
        1
    );

    status.map_epoch = 10;
    status.epoch_id = "7".repeat(64);
    status.root_hash = "8".repeat(64);
    status.finding_id = GOLDEN_FINDING_ID.to_owned();
    assert!(advance_status_floor(
        &floor_path,
        &status.floor_observation(),
        &authorization,
        &authorization_sha256,
    )
    .unwrap_err()
    .to_string()
    .contains("durably retracted"));
}

#[test]
fn status_floor_partitions_retractions_without_growing_the_epoch_document() {
    let dir = tempfile::tempdir().unwrap();
    let floor_path = dir.path().join("status-floor.json");
    for index in 0..300_u16 {
        let mut retracted = response("inclusion");
        retracted.finding_id = format!("{index:064x}");
        advance(&floor_path, &retracted).unwrap();
    }

    assert!(read_status_floor(&floor_path).unwrap().is_some());
    assert!(
        std::fs::metadata(&floor_path).unwrap().len() < 16 * 1024,
        "epoch floor exceeded its read bound"
    );
    let retraction_directory = dir.path().join("status-floor.json.retractions");
    assert_eq!(
        std::fs::read_dir(retraction_directory).unwrap().count(),
        300
    );

    let mut attempted_revival = response("non_inclusion");
    attempted_revival.finding_id = format!("{:064x}", 299_u16);
    attempted_revival.map_epoch = 9;
    attempted_revival.epoch_id = "5".repeat(64);
    attempted_revival.root_hash = "6".repeat(64);
    let error = advance(&floor_path, &attempted_revival)
        .unwrap_err()
        .to_string();
    assert!(error.contains("durably retracted"), "unexpected error: {error}");
}

#[test]
fn status_floor_lock_recovers_from_stale_sidecar_and_excludes_live_writer() {
    let dir = tempfile::tempdir().unwrap();
    let floor_path = dir.path().join("status-floor.json");
    std::fs::write(dir.path().join("status-floor.json.lock"), b"stale owner").unwrap();

    let first = FindingStatusFloorLock::acquire(&floor_path).unwrap();
    assert!(FindingStatusFloorLock::acquire(&floor_path).is_err());
    drop(first);
    FindingStatusFloorLock::acquire(&floor_path).unwrap();
}

#[test]
fn status_rejects_oversized_encoded_proof_before_decoding() {
    let authorization = authorization();
    let max_encoded_proof =
        (chio_finding::MAX_FINDING_STATUS_PROOF_BYTES.saturating_add(2) / 3)
            .saturating_mul(4);
    let mut status = response("non_inclusion");
    status.proof_input_b64 = "A".repeat(max_encoded_proof.saturating_add(1));

    let error = verify_status_projection(
        &status,
        &authorization.feed_id,
        GOLDEN_FINDING_ID,
        &authorization,
        &status.service_bond_evidence_sha256,
        300,
        status.checked_at,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("oversized"), "unexpected error: {error}");
}

#[test]
fn status_rejects_a_projected_digest_that_does_not_hash_the_proof_bytes() {
    use base64::Engine as _;

    let authorization = authorization();
    let mut status = response("non_inclusion");
    status.proof_input_b64 = base64::engine::general_purpose::STANDARD.encode(b"{}");

    let error = verify_status_projection(
        &status,
        &authorization.feed_id,
        GOLDEN_FINDING_ID,
        &authorization,
        &status.service_bond_evidence_sha256,
        300,
        status.checked_at,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("proof digest"), "unexpected error: {error}");
}

#[test]
fn status_operator_authorization_is_loaded_out_of_band_and_feed_pinned() {
    let dir = tempfile::tempdir().unwrap();
    let mut authorization = authorization();
    authorization.revoked_from = Some(1_850_000_000);
    let path = write_temp(
        &dir,
        "status-operator.json",
        &canonical_json_string(&authorization).unwrap(),
    );
    assert_eq!(
        load_status_operator_authorization(&path, "status-feed/venue-01").unwrap(),
        authorization
    );
    let error = load_status_operator_authorization(&path, "status-feed/elsewhere")
        .unwrap_err()
        .to_string();
    assert!(error.contains("different feed"), "unexpected error: {error}");
}

#[test]
fn status_service_bond_is_canonical_operator_bound_and_current() {
    let dir = tempfile::tempdir().unwrap();
    let authorization = authorization();
    let authorization_sha256 = sha256_hex(&canonical_json_bytes(&authorization).unwrap());
    let bond = chio_control_plane::trust_control::FindingStatusServiceBond {
        bond_id: "status-bond-01".to_owned(),
        feed_id: authorization.feed_id.clone(),
        operator_id: authorization.operator.authority_id.clone(),
        locked_units: 1_000,
        currency: "USD".to_owned(),
        valid_from: 1_799_999_000,
        valid_until: 1_800_010_000,
        inclusion_sla_secs: 600,
        missed_inclusion_slash_units: 100,
        equivocation_slash_units: 1_000,
        evidence_sha256: "a".repeat(64),
    };
    let path = write_temp(
        &dir,
        "status-bond.json",
        &canonical_json_string(&bond).unwrap(),
    );
    assert_eq!(
        load_status_service_bond(
            &path,
            &authorization.feed_id,
            &authorization,
            &authorization_sha256,
            1_800_000_000,
        )
        .unwrap(),
        bond
    );
    let error = load_status_service_bond(
        &path,
        &authorization.feed_id,
        &authorization,
        &authorization_sha256,
        bond.valid_until,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("not current"), "unexpected error: {error}");
}
