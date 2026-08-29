//! Exact signed challenge filing retention and integrity checks.

use super::*;

/// Bound on one exact signed challenge envelope.
const MAX_CHALLENGE_ENVELOPE_BYTES: usize = 1_048_576;

/// Exact signed filing bytes retained with the challenge row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingChallengeSubmissionEnvelopeRecord {
    pub challenge_id: String,
    pub challenge_envelope_sha256: String,
    pub challenge_envelope_json: Vec<u8>,
    pub recorded_at: u64,
}

impl SqliteFindingChallengeStore {
    /// Load the exact canonical signed filing retained for one challenge.
    pub fn get_challenge_submission(
        &self,
        challenge_id: &str,
    ) -> Result<Option<FindingChallengeSubmissionEnvelopeRecord>, FindingChallengeStoreError> {
        require_identifier(challenge_id, "challenge_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let record: Option<(String, String, Vec<u8>, i64)> = transaction
            .query_row(
                r#"
                SELECT challenge_id, challenge_envelope_sha256,
                       challenge_envelope_json, recorded_at
                FROM finding_challenge_submissions
                WHERE challenge_id = ?1
                "#,
                [challenge_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        record
            .map(
                |(
                    challenge_id,
                    challenge_envelope_sha256,
                    challenge_envelope_json,
                    recorded_at,
                )| {
                    validate_submission_record(FindingChallengeSubmissionEnvelopeRecord {
                        challenge_id,
                        challenge_envelope_sha256,
                        challenge_envelope_json,
                        recorded_at: stored_u64(recorded_at, "recorded_at")?,
                    })
                },
            )
            .transpose()
    }
}

pub(super) fn store_challenge_submission_tx(
    transaction: &Transaction<'_>,
    input: &FindingChallengeSubmission<'_>,
) -> Result<bool, FindingChallengeStoreError> {
    let inserted = transaction
        .execute(
            r#"
            INSERT OR IGNORE INTO finding_challenge_submissions (
                challenge_envelope_sha256, challenge_id,
                challenge_envelope_json, recorded_at
            ) VALUES (?1, ?2, ?3, ?4)
            "#,
            params![
                input.challenge_envelope_sha256,
                input.challenge_id,
                input.challenge_envelope_json,
                sqlite_i64(input.submitted_at, "submitted_at")?,
            ],
        )
        .map_err(sqlite_error)?;
    if inserted == 1 {
        return Ok(true);
    }
    let retained: Option<(String, Vec<u8>)> = transaction
        .query_row(
            r#"
            SELECT challenge_id, challenge_envelope_json
            FROM finding_challenge_submissions
            WHERE challenge_envelope_sha256 = ?1
            "#,
            [input.challenge_envelope_sha256],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    match retained {
        Some((challenge_id, bytes))
            if challenge_id == input.challenge_id && bytes == input.challenge_envelope_json =>
        {
            Ok(false)
        }
        Some(_) => Err(FindingChallengeStoreError::Conflict(
            "challenge envelope digest is bound to different retained bytes".to_owned(),
        )),
        None => Err(invariant(
            "ignored challenge envelope insert did not resolve retained bytes",
        )),
    }
}

pub(super) fn validate_submission(
    input: &FindingChallengeSubmission<'_>,
) -> Result<(), FindingChallengeStoreError> {
    require_identifier(input.challenge_id, "challenge_id")?;
    require_identifier(input.listing_id, "listing_id")?;
    require_hex64(input.finding_id, "finding_id")?;
    require_hex64(input.challenge_envelope_sha256, "challenge_envelope_sha256")?;
    require_canonical_challenge_envelope(
        input.challenge_envelope_json,
        input.challenge_envelope_sha256,
    )?;
    match (input.authorization_branch, input.challenger_hex) {
        (FindingChallengeAuthorizationBranch::BuyerSubmission, Some(challenger)) => {
            require_hex64(challenger, "challenger_hex")?;
        }
        (FindingChallengeAuthorizationBranch::BuyerSubmission, None) => {
            return Err(invariant("a buyer submission must name its challenger"));
        }
        (FindingChallengeAuthorizationBranch::VenueAudit, Some(_)) => {
            return Err(invariant("a venue audit must not name a challenger"));
        }
        (FindingChallengeAuthorizationBranch::VenueAudit, None) => {}
    }
    require_trusted_time(input.submitted_at, "submitted_at")
}

fn validate_submission_record(
    record: FindingChallengeSubmissionEnvelopeRecord,
) -> Result<FindingChallengeSubmissionEnvelopeRecord, FindingChallengeStoreError> {
    require_identifier(&record.challenge_id, "challenge_id")?;
    require_hex64(
        &record.challenge_envelope_sha256,
        "challenge_envelope_sha256",
    )?;
    require_canonical_challenge_envelope(
        &record.challenge_envelope_json,
        &record.challenge_envelope_sha256,
    )?;
    require_trusted_time(record.recorded_at, "recorded_at")?;
    Ok(record)
}

fn require_canonical_challenge_envelope(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<(), FindingChallengeStoreError> {
    if bytes.is_empty() || bytes.len() > MAX_CHALLENGE_ENVELOPE_BYTES {
        return Err(invariant(
            "signed challenge envelope exceeds its byte bound",
        ));
    }
    let raw = std::str::from_utf8(bytes)
        .map_err(|_| invariant("signed challenge envelope is not UTF-8"))?;
    let canonical = chio_core::canonical::canonical_json_bytes_from_str(raw)
        .map_err(|_| invariant("signed challenge envelope is not strict canonical JSON"))?;
    if canonical != bytes || sha256_hex(bytes) != expected_sha256 {
        return Err(invariant(
            "signed challenge envelope bytes do not match their digest",
        ));
    }
    Ok(())
}

pub(super) fn verify_challenge_submissions(
    connection: &Connection,
) -> Result<(), FindingChallengeStoreError> {
    let mut submissions = connection
        .prepare(
            r#"
            SELECT challenge_id, challenge_envelope_sha256,
                   challenge_envelope_json, recorded_at
            FROM finding_challenge_submissions
            ORDER BY challenge_id
            "#,
        )
        .map_err(sqlite_error)?;
    let retained = submissions
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    for (challenge_id, challenge_envelope_sha256, challenge_envelope_json, recorded_at) in retained
    {
        validate_submission_record(FindingChallengeSubmissionEnvelopeRecord {
            challenge_id,
            challenge_envelope_sha256,
            challenge_envelope_json,
            recorded_at: stored_u64(recorded_at, "recorded_at")?,
        })?;
    }
    let mismatched_submission = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM finding_challenge_submissions AS submission
                JOIN challenges AS challenge
                  ON challenge.challenge_id = submission.challenge_id
                WHERE challenge.challenge_envelope_sha256 <>
                      submission.challenge_envelope_sha256
            )
            "#,
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if mismatched_submission {
        return Err(invariant(
            "retained challenge envelope does not bind its challenge row",
        ));
    }
    Ok(())
}
