use super::*;
use crate::finding_challenge_store::{
    FindingChallengeAuthorizationBranch, FindingChallengeEvidenceClass, FindingChallengeSubmission,
};

#[test]
fn finding_challenge_projection_rejects_offline_state_tampering() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open");
    let challenge_envelope = br#"{"challenge":"tamper"}"#;
    authority
        .finding_challenge_store()
        .submit_challenge(&FindingChallengeSubmission {
            challenge_id: "tamper-challenge",
            finding_id: &"a".repeat(64),
            listing_id: "tamper-listing",
            challenge_envelope_sha256: &sha256_hex(challenge_envelope),
            challenge_envelope_json: challenge_envelope,
            authorization_branch: FindingChallengeAuthorizationBranch::BuyerSubmission,
            evidence_class: FindingChallengeEvidenceClass::EvidenceInvalid,
            challenger_hex: Some(&"b".repeat(64)),
            submitted_at: 1_750_000_000,
        })
        .expect("challenge mutation");
    drop(authority);

    let connection = Connection::open(&database).expect("open authority offline");
    assert_eq!(
        connection
            .execute(
                "UPDATE challenges SET updated_at = updated_at + 1 WHERE challenge_id = ?1",
                ["tamper-challenge"],
            )
            .expect("tamper challenge state"),
        1
    );
    drop(connection);
    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(_))
    ));
}

#[test]
fn finding_challenge_projection_rejects_retained_submission_tampering() {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open");
    let challenge_envelope = br#"{"challenge":"retained"}"#;
    authority
        .finding_challenge_store()
        .submit_challenge(&FindingChallengeSubmission {
            challenge_id: "retained-tamper-challenge",
            finding_id: &"a".repeat(64),
            listing_id: "retained-tamper-listing",
            challenge_envelope_sha256: &sha256_hex(challenge_envelope),
            challenge_envelope_json: challenge_envelope,
            authorization_branch: FindingChallengeAuthorizationBranch::BuyerSubmission,
            evidence_class: FindingChallengeEvidenceClass::EvidenceInvalid,
            challenger_hex: Some(&"b".repeat(64)),
            submitted_at: 1_750_000_000,
        })
        .expect("challenge mutation");
    drop(authority);

    let connection = Connection::open(&database).expect("open authority offline");
    assert_eq!(
        connection
            .execute(
                r#"
                UPDATE finding_challenge_submissions
                SET challenge_envelope_json = ?1
                WHERE challenge_id = ?2
                "#,
                params![
                    br#"{"challenge":"modified"}"#.as_slice(),
                    "retained-tamper-challenge"
                ],
            )
            .expect("tamper retained submission"),
        1
    );
    drop(connection);
    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(_))
    ));
}
