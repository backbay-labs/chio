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

/// One exact signed filing supplied to the offline retention repair path.
#[derive(Debug, Clone, Copy)]
pub struct FindingChallengeSubmissionRepairInput<'a> {
    pub challenge_id: &'a str,
    pub challenge_envelope_sha256: &'a str,
    pub challenge_envelope_json: &'a [u8],
}

/// Result of an atomic offline challenge-retention repair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FindingChallengeSubmissionRepairReport {
    pub inserted: u64,
    pub exact_replays: u64,
    pub schema_version: i32,
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

    /// Restore missing exact challenge filings into an offline v13 or v14
    /// database. The database must already contain the matching immutable
    /// challenge rows. Every supplied preimage is canonical and digest-bound,
    /// the whole repair commits atomically, and v13 is stamped v14 only after
    /// all current invariants pass.
    pub fn repair_challenge_submissions(
        database_path: &std::path::Path,
        inputs: &[FindingChallengeSubmissionRepairInput<'_>],
    ) -> Result<FindingChallengeSubmissionRepairReport, FindingChallengeStoreError> {
        if inputs.is_empty() || inputs.len() > 10_000 {
            return Err(invariant(
                "challenge submission repair bundle is empty or too large",
            ));
        }
        let mut connection = Connection::open_with_flags(
            database_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(sqlite_error)?;
        connection
            .execute_batch(
                "PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF; PRAGMA synchronous = FULL;",
            )
            .map_err(sqlite_error)?;
        let on_disk = crate::check_schema_version(
            &connection,
            FINDING_CHALLENGE_SCHEMA_KEY,
            FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION,
            FINDING_CHALLENGE_SCHEMA_ANCHORS,
        )
        .map_err(|error| invariant(error.to_string()))?;
        if !matches!(on_disk, 13 | FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION) {
            return Err(invariant(format!(
                "challenge submission repair requires schema revision 13 or 14, found {on_disk}",
            )));
        }
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Exclusive)
            .map_err(sqlite_error)?;
        if on_disk == 13 {
            replace_legacy_effect_root_binding_trigger(&transaction, on_disk)?;
            transaction
                .execute_batch(FINDING_CHALLENGE_SCHEMA)
                .map_err(sqlite_error)?;
        }
        let mut inserted = 0_u64;
        let mut exact_replays = 0_u64;
        for input in inputs {
            require_identifier(input.challenge_id, "challenge_id")?;
            require_hex64(input.challenge_envelope_sha256, "challenge_envelope_sha256")?;
            require_canonical_challenge_envelope(
                input.challenge_envelope_json,
                input.challenge_envelope_sha256,
            )?;
            let challenge: Option<(String, i64)> = transaction
                .query_row(
                    "SELECT challenge_envelope_sha256, submitted_at FROM challenges WHERE challenge_id = ?1",
                    [input.challenge_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(sqlite_error)?;
            let (expected_digest, submitted_at) =
                challenge.ok_or(FindingChallengeStoreError::NotFound)?;
            if expected_digest != input.challenge_envelope_sha256 {
                return Err(FindingChallengeStoreError::Conflict(
                    "repair filing digest does not match its challenge row".to_owned(),
                ));
            }
            let changed = transaction
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
                        submitted_at,
                    ],
                )
                .map_err(sqlite_error)?;
            let retained: Option<(String, Vec<u8>)> = transaction
                .query_row(
                    "SELECT challenge_envelope_sha256, challenge_envelope_json FROM finding_challenge_submissions WHERE challenge_id = ?1",
                    [input.challenge_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(sqlite_error)?;
            if retained
                .as_ref()
                .map(|(digest, bytes)| (digest.as_str(), bytes.as_slice()))
                != Some((
                    input.challenge_envelope_sha256,
                    input.challenge_envelope_json,
                ))
            {
                return Err(FindingChallengeStoreError::Conflict(
                    "repair filing conflicts with retained challenge bytes".to_owned(),
                ));
            }
            if changed == 1 {
                inserted = inserted
                    .checked_add(1)
                    .ok_or_else(|| invariant("challenge repair count overflow"))?;
            } else {
                exact_replays = exact_replays
                    .checked_add(1)
                    .ok_or_else(|| invariant("challenge repair count overflow"))?;
            }
        }
        if on_disk == 13 {
            crate::stamp_schema_version(
                &transaction,
                FINDING_CHALLENGE_SCHEMA_KEY,
                FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION,
            )
            .map_err(|error| invariant(error.to_string()))?;
        }
        verify_finding_challenge_invariants(&transaction)?;
        transaction.commit().map_err(sqlite_error)?;
        connection
            .execute_batch("PRAGMA wal_checkpoint(FULL);")
            .map_err(sqlite_error)?;
        Ok(FindingChallengeSubmissionRepairReport {
            inserted,
            exact_replays,
            schema_version: FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION,
        })
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
    let missing_submission = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM challenges AS challenge
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM finding_challenge_submissions AS submission
                    WHERE submission.challenge_id = challenge.challenge_id
                      AND submission.challenge_envelope_sha256 =
                          challenge.challenge_envelope_sha256
                )
            )
            "#,
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if missing_submission {
        return Err(invariant(
            "challenge row has no exact retained signed submission",
        ));
    }
    Ok(())
}
