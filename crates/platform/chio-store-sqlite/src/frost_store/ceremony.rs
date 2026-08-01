use std::collections::BTreeMap;

use chio_core::canonical::canonical_json_bytes;
use chio_core::{sha256_hex, StoreMutationFence};
use chio_federation_authority::{
    advance_frost_ceremony, begin_frost_ceremony, complete_frost_ceremony,
    verify_frost_ceremony_round1_transcript, verify_frost_ceremony_transcript,
    FrostAuthenticatedDkgPackage, FrostCeremonyConfig, FrostCeremonySecret,
    FrostCeremonySecretKind,
};
use rand_core::{CryptoRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use serde::Serialize;
use zeroize::Zeroizing;

use super::commit::{
    append_projection_commit, prefixed_digest, verify_projection_commit_chains, ProjectionMutation,
};
use super::{
    secret_kind_name, FrostCeremonyRecord, FrostCeremonyRound1Record, FrostCeremonyRound2Record,
    FrostCeremonyState, FrostCustodyKey, FrostStoreError, SqliteFrostStore, StoredCeremonyOutput,
    StoredFrostCeremonyCompletion,
};
use crate::encrypted_blob::{decrypt_blob_with_aad, try_encrypt_blob_with_aad, EncryptedBlob};

const CUSTODY_AAD_FORMAT: &str = "chio.frost.ceremony-custody-aad.v1";
const RECORD_DIGEST_PREFIX: &[u8] = b"chio.frost.ceremony-record.digest.v1\0";

#[derive(Debug)]
struct StoredCeremonyRow {
    ceremony_id: String,
    config_json: Vec<u8>,
    config_digest: String,
    participant_set_digest: String,
    scope_id: String,
    key_epoch: u64,
    local_participant_id: String,
    state: FrostCeremonyState,
    state_version: u64,
    custody_generation: String,
    secret_kind: String,
    secret: EncryptedBlob,
    output: Option<EncryptedBlob>,
    input_transcript_digest: Option<String>,
    public_key_package: Option<Vec<u8>>,
    group_public_key: Option<String>,
    verification_shares_json: Option<Vec<u8>>,
    source_fence: StoreMutationFence,
    updated_at_unix_ms: u64,
    completed_at_unix_ms: Option<u64>,
    record_digest: String,
}

struct CeremonyWrite<'a> {
    ceremony_id: &'a str,
    config_json: &'a [u8],
    config_digest: &'a str,
    participant_set_digest: &'a str,
    scope_id: &'a str,
    key_epoch: u64,
    local_participant_id: &'a str,
    state: FrostCeremonyState,
    state_version: u64,
    custody_generation: &'a str,
    secret_kind: &'a str,
    secret: &'a EncryptedBlob,
    output: Option<&'a EncryptedBlob>,
    input_transcript_digest: Option<&'a str>,
    public_key_package: Option<&'a [u8]>,
    group_public_key: Option<&'a str>,
    verification_shares_json: Option<&'a [u8]>,
    source_fence: &'a StoreMutationFence,
    updated_at_unix_ms: u64,
    completed_at_unix_ms: Option<u64>,
}

struct CustodyBinding<'a> {
    ceremony_id: &'a str,
    config_digest: &'a str,
    state: FrostCeremonyState,
    state_version: u64,
    custody_generation: &'a str,
    fence: &'a StoreMutationFence,
    updated_at_unix_ms: u64,
}

impl StoredCeremonyRow {
    fn custody_binding(&self) -> CustodyBinding<'_> {
        CustodyBinding {
            ceremony_id: &self.ceremony_id,
            config_digest: &self.config_digest,
            state: self.state,
            state_version: self.state_version,
            custody_generation: &self.custody_generation,
            fence: &self.source_fence,
            updated_at_unix_ms: self.updated_at_unix_ms,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CustodyAad<'a> {
    format: &'static str,
    purpose: &'a str,
    ceremony_id: &'a str,
    config_digest: &'a str,
    state: FrostCeremonyState,
    state_version: u64,
    custody_generation: &'a str,
    store_uuid: &'a str,
    store_lease_id: &'a str,
    store_owner_epoch: u64,
    updated_at_unix_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordDigestPreimage<'a> {
    format: &'static str,
    ceremony_id: &'a str,
    config_digest: &'a str,
    participant_set_digest: &'a str,
    scope_id: &'a str,
    key_epoch: u64,
    local_participant_id: &'a str,
    state: FrostCeremonyState,
    state_version: u64,
    custody_generation: &'a str,
    secret_kind: &'a str,
    secret_nonce: String,
    secret_ciphertext_digest: String,
    output_nonce: Option<String>,
    output_ciphertext_digest: Option<String>,
    input_transcript_digest: Option<&'a str>,
    public_key_package_digest: Option<String>,
    group_public_key: Option<&'a str>,
    verification_shares_digest: Option<String>,
    store_uuid: &'a str,
    store_lease_id: &'a str,
    store_owner_epoch: u64,
    updated_at_unix_ms: u64,
    completed_at_unix_ms: Option<u64>,
}

impl SqliteFrostStore {
    #[allow(clippy::too_many_arguments)]
    pub fn begin_ceremony<R: CryptoRng + RngCore>(
        &self,
        config: &FrostCeremonyConfig,
        transport_key: &chio_core::Keypair,
        custody: &FrostCustodyKey,
        rng: &mut R,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<FrostCeremonyRound1Record, FrostStoreError> {
        validate_trusted_time(trusted_now_unix_ms)?;
        let ceremony_id = config.ceremony_id()?;
        let config_json = canonical_json_bytes(config)
            .map_err(|error| FrostStoreError::InvalidState(error.to_string()))?;
        let config_digest = sha256_hex(&config_json);
        let participant_set_digest = config.participant_set_digest()?;

        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        if let Some(stored) = load_ceremony_tx(&transaction, &ceremony_id)? {
            verify_exact_config(&stored, &config_digest, custody, trusted_now_unix_ms)?;
            if stored.state != FrostCeremonyState::Round1Ready {
                return Err(FrostStoreError::Conflict(
                    "ceremony already advanced beyond round one",
                ));
            }
            let output = decrypt_output(&stored, custody)?;
            let StoredCeremonyOutput::Round1(package) = output else {
                return Err(invalid("round-one state retained another output kind"));
            };
            transaction.commit().map_err(super::sqlite_error)?;
            return Ok(FrostCeremonyRound1Record {
                ceremony_id,
                state: stored.state,
                state_version: stored.state_version,
                package: *package,
            });
        }
        let conflicting = transaction
            .query_row(
                r#"
                SELECT ceremony_id FROM frost_ceremonies
                WHERE scope_id = ?1 AND key_epoch = ?2 AND local_participant_id = ?3
                "#,
                params![
                    &config.scope_id,
                    sqlite_u64(config.key_epoch, "ceremony key epoch")?,
                    &config.local_participant_id,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(super::sqlite_error)?;
        if conflicting.is_some() {
            return Err(FrostStoreError::Conflict(
                "another participant set already owns this scope and epoch",
            ));
        }

        let transition = begin_frost_ceremony(config, transport_key, rng)?;
        let state = FrostCeremonyState::Round1Ready;
        let state_version = 1;
        let custody_binding = CustodyBinding {
            ceremony_id: &ceremony_id,
            config_digest: &config_digest,
            state,
            state_version,
            custody_generation: custody.generation(),
            fence,
            updated_at_unix_ms: trusted_now_unix_ms,
        };
        let secret = encrypt_material(
            transition.secret.custody_bytes(),
            custody,
            &custody_aad("secret", &custody_binding)?,
        )?;
        let output_bytes = Zeroizing::new(
            canonical_json_bytes(&StoredCeremonyOutput::Round1(Box::new(
                transition.package.clone(),
            )))
            .map_err(|error| FrostStoreError::InvalidState(error.to_string()))?,
        );
        let output = encrypt_material(
            &output_bytes,
            custody,
            &custody_aad("output", &custody_binding)?,
        )?;
        let write = CeremonyWrite {
            ceremony_id: &ceremony_id,
            config_json: &config_json,
            config_digest: &config_digest,
            participant_set_digest: &participant_set_digest,
            scope_id: &config.scope_id,
            key_epoch: config.key_epoch,
            local_participant_id: &config.local_participant_id,
            state,
            state_version,
            custody_generation: custody.generation(),
            secret_kind: secret_kind_name(&transition.secret),
            secret: &secret,
            output: Some(&output),
            input_transcript_digest: None,
            public_key_package: None,
            group_public_key: None,
            verification_shares_json: None,
            source_fence: fence,
            updated_at_unix_ms: trusted_now_unix_ms,
            completed_at_unix_ms: None,
        };
        let record_digest = record_digest(&write)?;
        insert_ceremony(&transaction, &write, &record_digest)?;
        append_projection_commit(
            &transaction,
            self,
            &projection_key(&ceremony_id),
            ProjectionMutation {
                sequence: state_version,
                projection_type: "ceremony",
                mutation_kind: "frost.ceremony.begin",
                record_digest: &record_digest,
            },
            fence,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FrostCeremonyRound1Record {
            ceremony_id,
            state,
            state_version,
            package: transition.package,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn advance_ceremony(
        &self,
        config: &FrostCeremonyConfig,
        transport_key: &chio_core::Keypair,
        custody: &FrostCustodyKey,
        round1_packages: &[FrostAuthenticatedDkgPackage],
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<FrostCeremonyRound2Record, FrostStoreError> {
        validate_trusted_time(trusted_now_unix_ms)?;
        let ceremony_id = config.ceremony_id()?;
        let config_json = canonical_json_bytes(config)
            .map_err(|error| FrostStoreError::InvalidState(error.to_string()))?;
        let config_digest = sha256_hex(&config_json);
        let round1_digest = verify_frost_ceremony_round1_transcript(config, round1_packages)?;

        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        let stored = load_ceremony_tx(&transaction, &ceremony_id)?
            .ok_or(FrostStoreError::Conflict("ceremony has not started"))?;
        verify_exact_config(&stored, &config_digest, custody, trusted_now_unix_ms)?;
        if stored.state == FrostCeremonyState::Round2Ready {
            if stored.input_transcript_digest.as_deref() != Some(&round1_digest) {
                return Err(FrostStoreError::Conflict(
                    "round-one transcript changed after advancement",
                ));
            }
            let output = decrypt_output(&stored, custody)?;
            let StoredCeremonyOutput::Round2(packages) = output else {
                return Err(invalid("round-two state retained another output kind"));
            };
            transaction.commit().map_err(super::sqlite_error)?;
            return Ok(FrostCeremonyRound2Record {
                ceremony_id,
                state: stored.state,
                state_version: stored.state_version,
                packages,
                round1_transcript_digest: round1_digest,
            });
        }
        if stored.state != FrostCeremonyState::Round1Ready || stored.state_version != 1 {
            return Err(FrostStoreError::Conflict(
                "ceremony cannot advance from its current state",
            ));
        }
        let round1_secret = decrypt_secret(&stored, custody)?;
        let transition =
            advance_frost_ceremony(config, transport_key, round1_secret, round1_packages)?;
        if transition.round1_transcript_digest != round1_digest {
            return Err(invalid(
                "authority returned a different round-one transcript",
            ));
        }
        let state = FrostCeremonyState::Round2Ready;
        let state_version = 2;
        let custody_binding = CustodyBinding {
            ceremony_id: &ceremony_id,
            config_digest: &config_digest,
            state,
            state_version,
            custody_generation: custody.generation(),
            fence,
            updated_at_unix_ms: trusted_now_unix_ms,
        };
        let secret = encrypt_material(
            transition.secret.custody_bytes(),
            custody,
            &custody_aad("secret", &custody_binding)?,
        )?;
        let output_bytes = Zeroizing::new(
            canonical_json_bytes(&StoredCeremonyOutput::Round2(transition.packages.clone()))
                .map_err(|error| FrostStoreError::InvalidState(error.to_string()))?,
        );
        let output = encrypt_material(
            &output_bytes,
            custody,
            &custody_aad("output", &custody_binding)?,
        )?;
        let write = CeremonyWrite {
            ceremony_id: &ceremony_id,
            config_json: &config_json,
            config_digest: &config_digest,
            participant_set_digest: &stored.participant_set_digest,
            scope_id: &stored.scope_id,
            key_epoch: stored.key_epoch,
            local_participant_id: &stored.local_participant_id,
            state,
            state_version,
            custody_generation: custody.generation(),
            secret_kind: secret_kind_name(&transition.secret),
            secret: &secret,
            output: Some(&output),
            input_transcript_digest: Some(&round1_digest),
            public_key_package: None,
            group_public_key: None,
            verification_shares_json: None,
            source_fence: fence,
            updated_at_unix_ms: trusted_now_unix_ms,
            completed_at_unix_ms: None,
        };
        let record_digest = record_digest(&write)?;
        update_ceremony(&transaction, &write, &record_digest, 1)?;
        append_projection_commit(
            &transaction,
            self,
            &projection_key(&ceremony_id),
            ProjectionMutation {
                sequence: state_version,
                projection_type: "ceremony",
                mutation_kind: "frost.ceremony.advance",
                record_digest: &record_digest,
            },
            fence,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FrostCeremonyRound2Record {
            ceremony_id,
            state,
            state_version,
            packages: transition.packages,
            round1_transcript_digest: round1_digest,
        })
    }

    pub fn complete_ceremony(
        &self,
        config: &FrostCeremonyConfig,
        custody: &FrostCustodyKey,
        round1_packages: &[FrostAuthenticatedDkgPackage],
        round2_packages: &[FrostAuthenticatedDkgPackage],
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<StoredFrostCeremonyCompletion, FrostStoreError> {
        validate_trusted_time(trusted_now_unix_ms)?;
        let ceremony_id = config.ceremony_id()?;
        let config_json = canonical_json_bytes(config)
            .map_err(|error| FrostStoreError::InvalidState(error.to_string()))?;
        let config_digest = sha256_hex(&config_json);
        let transcript_digest =
            verify_frost_ceremony_transcript(config, round1_packages, round2_packages)?;

        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        let stored = load_ceremony_tx(&transaction, &ceremony_id)?
            .ok_or(FrostStoreError::Conflict("ceremony has not started"))?;
        verify_exact_config(&stored, &config_digest, custody, trusted_now_unix_ms)?;
        if stored.state == FrostCeremonyState::Completed {
            if stored.input_transcript_digest.as_deref() != Some(&transcript_digest) {
                return Err(FrostStoreError::Conflict(
                    "ceremony transcript changed after completion",
                ));
            }
            let completion = completion_from_row(&stored)?;
            transaction.commit().map_err(super::sqlite_error)?;
            return Ok(completion);
        }
        if stored.state != FrostCeremonyState::Round2Ready || stored.state_version != 2 {
            return Err(FrostStoreError::Conflict(
                "ceremony cannot complete from its current state",
            ));
        }
        let round2_secret = decrypt_secret(&stored, custody)?;
        let completion =
            complete_frost_ceremony(config, round2_secret, round1_packages, round2_packages)?;
        if completion.transcript_digest != transcript_digest {
            return Err(invalid(
                "authority returned a different ceremony transcript",
            ));
        }
        let state = FrostCeremonyState::Completed;
        let state_version = 3;
        let custody_binding = CustodyBinding {
            ceremony_id: &ceremony_id,
            config_digest: &config_digest,
            state,
            state_version,
            custody_generation: custody.generation(),
            fence,
            updated_at_unix_ms: trusted_now_unix_ms,
        };
        let secret = encrypt_material(
            completion.key_package.custody_bytes(),
            custody,
            &custody_aad("secret", &custody_binding)?,
        )?;
        let verification_shares_json = canonical_json_bytes(&completion.verification_shares)
            .map_err(|error| FrostStoreError::InvalidState(error.to_string()))?;
        let write = CeremonyWrite {
            ceremony_id: &ceremony_id,
            config_json: &config_json,
            config_digest: &config_digest,
            participant_set_digest: &stored.participant_set_digest,
            scope_id: &stored.scope_id,
            key_epoch: stored.key_epoch,
            local_participant_id: &stored.local_participant_id,
            state,
            state_version,
            custody_generation: custody.generation(),
            secret_kind: secret_kind_name(&completion.key_package),
            secret: &secret,
            output: None,
            input_transcript_digest: Some(&transcript_digest),
            public_key_package: Some(&completion.public_key_package),
            group_public_key: Some(&completion.group_public_key),
            verification_shares_json: Some(&verification_shares_json),
            source_fence: fence,
            updated_at_unix_ms: trusted_now_unix_ms,
            completed_at_unix_ms: Some(trusted_now_unix_ms),
        };
        let record_digest = record_digest(&write)?;
        update_ceremony(&transaction, &write, &record_digest, 2)?;
        append_projection_commit(
            &transaction,
            self,
            &projection_key(&ceremony_id),
            ProjectionMutation {
                sequence: state_version,
                projection_type: "ceremony",
                mutation_kind: "frost.ceremony.complete",
                record_digest: &record_digest,
            },
            fence,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(StoredFrostCeremonyCompletion {
            ceremony_id,
            state,
            state_version,
            public_key_package: completion.public_key_package,
            group_public_key: completion.group_public_key,
            verification_shares: completion.verification_shares,
            transcript_digest,
        })
    }

    pub fn load_ceremony(
        &self,
        ceremony_id: &str,
        custody: &FrostCustodyKey,
    ) -> Result<Option<FrostCeremonyRecord>, FrostStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection, None)?;
        let Some(stored) = load_ceremony_tx(&transaction, ceremony_id)? else {
            transaction.commit().map_err(super::sqlite_error)?;
            return Ok(None);
        };
        drop(decrypt_secret(&stored, custody)?);
        let record = public_record(&stored);
        transaction.commit().map_err(super::sqlite_error)?;
        Ok(Some(record))
    }

    pub fn load_completed_key_package(
        &self,
        ceremony_id: &str,
        custody: &FrostCustodyKey,
        fence: &StoreMutationFence,
    ) -> Result<FrostCeremonySecret, FrostStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection, Some(fence))?;
        let stored = load_ceremony_tx(&transaction, ceremony_id)?
            .ok_or(FrostStoreError::Conflict("ceremony is absent"))?;
        if stored.state != FrostCeremonyState::Completed {
            return Err(FrostStoreError::Conflict("ceremony is not complete"));
        }
        let secret = decrypt_secret(&stored, custody)?;
        transaction.commit().map_err(super::sqlite_error)?;
        Ok(secret)
    }
}

pub(super) fn verify_ceremony_invariants(connection: &Connection) -> Result<(), FrostStoreError> {
    let mut statement = connection
        .prepare("SELECT ceremony_id FROM frost_ceremonies ORDER BY ceremony_id")
        .map_err(super::sqlite_error)?;
    let ids = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(super::sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(super::sqlite_error)?;
    drop(statement);
    for ceremony_id in ids {
        let stored = load_ceremony_connection(connection, &ceremony_id)?
            .ok_or_else(|| invalid("ceremony disappeared during invariant verification"))?;
        verify_stored_row(&stored)?;
        let latest = connection
            .query_row(
                r#"
                SELECT projection_sequence, record_digest
                FROM frost_projection_commits
                WHERE projection_key = ?1
                ORDER BY projection_sequence DESC LIMIT 1
                "#,
                [projection_key(&ceremony_id)],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(super::sqlite_error)?
            .ok_or_else(|| invalid("ceremony has no projection commit"))?;
        if read_u64(latest.0, "projection sequence")? != stored.state_version
            || latest.1 != stored.record_digest
        {
            return Err(invalid(
                "ceremony does not match its latest projection commit",
            ));
        }
    }
    verify_projection_commit_chains(connection)
}

fn insert_ceremony(
    transaction: &Transaction<'_>,
    write: &CeremonyWrite<'_>,
    digest: &str,
) -> Result<(), FrostStoreError> {
    let changed = transaction
        .execute(
            r#"
            INSERT INTO frost_ceremonies (
                ceremony_id, config_json, config_digest, participant_set_digest,
                scope_id, key_epoch, local_participant_id, state, state_version,
                custody_generation, secret_kind, secret_nonce, secret_ciphertext,
                output_nonce, output_ciphertext, input_transcript_digest,
                public_key_package, group_public_key, verification_shares_json,
                source_store_uuid, source_lease_id, source_owner_epoch,
                updated_at_unix_ms, completed_at_unix_ms, record_digest
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19,
                ?20, ?21, ?22, ?23, ?24, ?25
            )
            "#,
            rusqlite::params_from_iter(ceremony_param_values(write, digest)?),
        )
        .map_err(super::sqlite_error)?;
    if changed != 1 {
        return Err(FrostStoreError::Conflict("ceremony insert lost its CAS"));
    }
    Ok(())
}

fn update_ceremony(
    transaction: &Transaction<'_>,
    write: &CeremonyWrite<'_>,
    digest: &str,
    expected_version: u64,
) -> Result<(), FrostStoreError> {
    let changed = transaction
        .execute(
            r#"
            UPDATE frost_ceremonies SET
                config_json = ?2, config_digest = ?3, participant_set_digest = ?4,
                scope_id = ?5, key_epoch = ?6, local_participant_id = ?7,
                state = ?8, state_version = ?9, custody_generation = ?10,
                secret_kind = ?11, secret_nonce = ?12, secret_ciphertext = ?13,
                output_nonce = ?14, output_ciphertext = ?15,
                input_transcript_digest = ?16, public_key_package = ?17,
                group_public_key = ?18, verification_shares_json = ?19,
                source_store_uuid = ?20, source_lease_id = ?21,
                source_owner_epoch = ?22, updated_at_unix_ms = ?23,
                completed_at_unix_ms = ?24, record_digest = ?25
            WHERE ceremony_id = ?1 AND state_version = ?26
            "#,
            rusqlite::params_from_iter(ceremony_param_values(write, digest)?.into_iter().chain([
                rusqlite::types::Value::Integer(sqlite_u64(
                    expected_version,
                    "expected ceremony version",
                )?),
            ])),
        )
        .map_err(super::sqlite_error)?;
    if changed != 1 {
        return Err(FrostStoreError::Fenced);
    }
    Ok(())
}

fn ceremony_param_values(
    write: &CeremonyWrite<'_>,
    digest: &str,
) -> Result<Vec<rusqlite::types::Value>, FrostStoreError> {
    use rusqlite::types::Value;
    let completed_at = match write.completed_at_unix_ms {
        Some(value) => Value::Integer(sqlite_u64(value, "ceremony completion time")?),
        None => Value::Null,
    };
    Ok(vec![
        Value::Text(write.ceremony_id.to_string()),
        Value::Blob(write.config_json.to_vec()),
        Value::Text(write.config_digest.to_string()),
        Value::Text(write.participant_set_digest.to_string()),
        Value::Text(write.scope_id.to_string()),
        Value::Integer(sqlite_u64(write.key_epoch, "ceremony key epoch")?),
        Value::Text(write.local_participant_id.to_string()),
        Value::Text(write.state.as_str().to_string()),
        Value::Integer(sqlite_u64(write.state_version, "ceremony state version")?),
        Value::Text(write.custody_generation.to_string()),
        Value::Text(write.secret_kind.to_string()),
        Value::Blob(write.secret.nonce.to_vec()),
        Value::Blob(write.secret.ciphertext.clone()),
        write
            .output
            .map_or(Value::Null, |output| Value::Blob(output.nonce.to_vec())),
        write
            .output
            .map_or(Value::Null, |output| Value::Blob(output.ciphertext.clone())),
        write
            .input_transcript_digest
            .map_or(Value::Null, |value| Value::Text(value.to_string())),
        write
            .public_key_package
            .map_or(Value::Null, |value| Value::Blob(value.to_vec())),
        write
            .group_public_key
            .map_or(Value::Null, |value| Value::Text(value.to_string())),
        write
            .verification_shares_json
            .map_or(Value::Null, |value| Value::Blob(value.to_vec())),
        Value::Text(write.source_fence.store_uuid.clone()),
        Value::Text(write.source_fence.lease_id.clone()),
        Value::Integer(sqlite_u64(
            write.source_fence.owner_epoch,
            "ceremony source owner epoch",
        )?),
        Value::Integer(sqlite_u64(
            write.updated_at_unix_ms,
            "ceremony updated time",
        )?),
        completed_at,
        Value::Text(digest.to_string()),
    ])
}

fn load_ceremony_tx(
    transaction: &Transaction<'_>,
    ceremony_id: &str,
) -> Result<Option<StoredCeremonyRow>, FrostStoreError> {
    load_ceremony_query(transaction, ceremony_id)
}

fn load_ceremony_connection(
    connection: &Connection,
    ceremony_id: &str,
) -> Result<Option<StoredCeremonyRow>, FrostStoreError> {
    load_ceremony_query(connection, ceremony_id)
}

fn load_ceremony_query(
    connection: &Connection,
    ceremony_id: &str,
) -> Result<Option<StoredCeremonyRow>, FrostStoreError> {
    let row = connection
        .query_row(
            r#"
            SELECT ceremony_id, config_json, config_digest, participant_set_digest,
                   scope_id, key_epoch, local_participant_id, state, state_version,
                   custody_generation, secret_kind, secret_nonce, secret_ciphertext,
                   output_nonce, output_ciphertext, input_transcript_digest,
                   public_key_package, group_public_key, verification_shares_json,
                   source_store_uuid, source_lease_id, source_owner_epoch,
                   updated_at_unix_ms, completed_at_unix_ms, record_digest
            FROM frost_ceremonies WHERE ceremony_id = ?1
            "#,
            [ceremony_id],
            decode_row,
        )
        .optional()
        .map_err(super::sqlite_error)?;
    if let Some(stored) = row.as_ref() {
        verify_stored_row(stored)?;
    }
    Ok(row)
}

fn decode_row(row: &Row<'_>) -> Result<StoredCeremonyRow, rusqlite::Error> {
    let secret_nonce = nonce_from_row(row, 11)?;
    let output_nonce = row
        .get::<_, Option<Vec<u8>>>(13)?
        .map(|bytes| nonce_from_bytes(bytes, 13))
        .transpose()?;
    let output_ciphertext = row.get::<_, Option<Vec<u8>>>(14)?;
    let output = match (output_nonce, output_ciphertext) {
        (Some(nonce), Some(ciphertext)) => Some(EncryptedBlob { nonce, ciphertext }),
        (None, None) => None,
        _ => {
            return Err(rusqlite::Error::InvalidColumnType(
                13,
                "output_nonce".to_string(),
                rusqlite::types::Type::Null,
            ));
        }
    };
    Ok(StoredCeremonyRow {
        ceremony_id: row.get(0)?,
        config_json: row.get(1)?,
        config_digest: row.get(2)?,
        participant_set_digest: row.get(3)?,
        scope_id: row.get(4)?,
        key_epoch: sqlite_read_u64(row, 5)?,
        local_participant_id: row.get(6)?,
        state: FrostCeremonyState::parse(&row.get::<_, String>(7)?)
            .map_err(|error| rusqlite::Error::InvalidParameterName(error.to_string()))?,
        state_version: sqlite_read_u64(row, 8)?,
        custody_generation: row.get(9)?,
        secret_kind: row.get(10)?,
        secret: EncryptedBlob {
            nonce: secret_nonce,
            ciphertext: row.get(12)?,
        },
        output,
        input_transcript_digest: row.get(15)?,
        public_key_package: row.get(16)?,
        group_public_key: row.get(17)?,
        verification_shares_json: row.get(18)?,
        source_fence: StoreMutationFence {
            store_uuid: row.get(19)?,
            lease_id: row.get(20)?,
            owner_epoch: sqlite_read_u64(row, 21)?,
        },
        updated_at_unix_ms: sqlite_read_u64(row, 22)?,
        completed_at_unix_ms: row
            .get::<_, Option<i64>>(23)?
            .map(|value| {
                u64::try_from(value)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(23, value))
            })
            .transpose()?,
        record_digest: row.get(24)?,
    })
}

fn verify_stored_row(stored: &StoredCeremonyRow) -> Result<(), FrostStoreError> {
    let config: FrostCeremonyConfig = serde_json::from_slice(&stored.config_json)
        .map_err(|error| invalid(format!("ceremony config does not decode: {error}")))?;
    config.validate()?;
    if config.ceremony_id()? != stored.ceremony_id
        || sha256_hex(&stored.config_json) != stored.config_digest
        || config.participant_set_digest()? != stored.participant_set_digest
        || config.scope_id != stored.scope_id
        || config.key_epoch != stored.key_epoch
        || config.local_participant_id != stored.local_participant_id
    {
        return Err(invalid("ceremony config binding is invalid"));
    }
    let expected_version = match stored.state {
        FrostCeremonyState::Round1Ready => 1,
        FrostCeremonyState::Round2Ready => 2,
        FrostCeremonyState::Completed => 3,
    };
    if stored.state_version != expected_version {
        return Err(invalid("ceremony state version is invalid"));
    }
    let write = row_as_write(stored);
    if record_digest(&write)? != stored.record_digest {
        return Err(invalid("ceremony record digest does not match"));
    }
    Ok(())
}

fn verify_exact_config(
    stored: &StoredCeremonyRow,
    config_digest: &str,
    custody: &FrostCustodyKey,
    trusted_now_unix_ms: u64,
) -> Result<(), FrostStoreError> {
    if stored.config_digest != config_digest {
        return Err(FrostStoreError::Conflict("ceremony configuration changed"));
    }
    if stored.custody_generation != custody.generation() {
        return Err(FrostStoreError::Custody(
            "custody generation does not match the ceremony",
        ));
    }
    if trusted_now_unix_ms < stored.updated_at_unix_ms {
        return Err(FrostStoreError::Conflict(
            "trusted time regressed behind the ceremony",
        ));
    }
    Ok(())
}

fn decrypt_secret(
    stored: &StoredCeremonyRow,
    custody: &FrostCustodyKey,
) -> Result<FrostCeremonySecret, FrostStoreError> {
    verify_custody_generation(stored, custody)?;
    let plaintext = decrypt_blob_with_aad(
        custody.key(),
        &stored.secret,
        &custody_aad("secret", &stored.custody_binding())?,
    )
    .map_err(|_| FrostStoreError::Custody("ceremony secret authentication failed"))?;
    FrostCeremonySecret::from_custody_bytes(
        parse_secret_kind(&stored.secret_kind)?,
        Zeroizing::new(plaintext),
    )
    .map_err(Into::into)
}

fn decrypt_output(
    stored: &StoredCeremonyRow,
    custody: &FrostCustodyKey,
) -> Result<StoredCeremonyOutput, FrostStoreError> {
    verify_custody_generation(stored, custody)?;
    let output = stored
        .output
        .as_ref()
        .ok_or_else(|| invalid("ceremony output is absent"))?;
    let plaintext = Zeroizing::new(
        decrypt_blob_with_aad(
            custody.key(),
            output,
            &custody_aad("output", &stored.custody_binding())?,
        )
        .map_err(|_| FrostStoreError::Custody("ceremony output authentication failed"))?,
    );
    serde_json::from_slice(&plaintext)
        .map_err(|error| invalid(format!("ceremony output does not decode: {error}")))
}

fn completion_from_row(
    stored: &StoredCeremonyRow,
) -> Result<StoredFrostCeremonyCompletion, FrostStoreError> {
    let verification_shares = serde_json::from_slice::<BTreeMap<String, String>>(
        stored
            .verification_shares_json
            .as_deref()
            .ok_or_else(|| invalid("completed ceremony lacks verification shares"))?,
    )
    .map_err(|error| invalid(format!("verification shares do not decode: {error}")))?;
    Ok(StoredFrostCeremonyCompletion {
        ceremony_id: stored.ceremony_id.clone(),
        state: stored.state,
        state_version: stored.state_version,
        public_key_package: stored
            .public_key_package
            .clone()
            .ok_or_else(|| invalid("completed ceremony lacks a public key package"))?,
        group_public_key: stored
            .group_public_key
            .clone()
            .ok_or_else(|| invalid("completed ceremony lacks a group public key"))?,
        verification_shares,
        transcript_digest: stored
            .input_transcript_digest
            .clone()
            .ok_or_else(|| invalid("completed ceremony lacks a transcript digest"))?,
    })
}

fn public_record(stored: &StoredCeremonyRow) -> FrostCeremonyRecord {
    FrostCeremonyRecord {
        ceremony_id: stored.ceremony_id.clone(),
        state: stored.state,
        state_version: stored.state_version,
        participant_set_digest: stored.participant_set_digest.clone(),
        scope_id: stored.scope_id.clone(),
        key_epoch: stored.key_epoch,
        local_participant_id: stored.local_participant_id.clone(),
        input_transcript_digest: stored.input_transcript_digest.clone(),
    }
}

fn row_as_write(stored: &StoredCeremonyRow) -> CeremonyWrite<'_> {
    CeremonyWrite {
        ceremony_id: &stored.ceremony_id,
        config_json: &stored.config_json,
        config_digest: &stored.config_digest,
        participant_set_digest: &stored.participant_set_digest,
        scope_id: &stored.scope_id,
        key_epoch: stored.key_epoch,
        local_participant_id: &stored.local_participant_id,
        state: stored.state,
        state_version: stored.state_version,
        custody_generation: &stored.custody_generation,
        secret_kind: &stored.secret_kind,
        secret: &stored.secret,
        output: stored.output.as_ref(),
        input_transcript_digest: stored.input_transcript_digest.as_deref(),
        public_key_package: stored.public_key_package.as_deref(),
        group_public_key: stored.group_public_key.as_deref(),
        verification_shares_json: stored.verification_shares_json.as_deref(),
        source_fence: &stored.source_fence,
        updated_at_unix_ms: stored.updated_at_unix_ms,
        completed_at_unix_ms: stored.completed_at_unix_ms,
    }
}

fn record_digest(write: &CeremonyWrite<'_>) -> Result<String, FrostStoreError> {
    let preimage = RecordDigestPreimage {
        format: "chio.frost.ceremony-record.v1",
        ceremony_id: write.ceremony_id,
        config_digest: write.config_digest,
        participant_set_digest: write.participant_set_digest,
        scope_id: write.scope_id,
        key_epoch: write.key_epoch,
        local_participant_id: write.local_participant_id,
        state: write.state,
        state_version: write.state_version,
        custody_generation: write.custody_generation,
        secret_kind: write.secret_kind,
        secret_nonce: hex::encode(write.secret.nonce),
        secret_ciphertext_digest: sha256_hex(&write.secret.ciphertext),
        output_nonce: write.output.map(|output| hex::encode(output.nonce)),
        output_ciphertext_digest: write.output.map(|output| sha256_hex(&output.ciphertext)),
        input_transcript_digest: write.input_transcript_digest,
        public_key_package_digest: write.public_key_package.map(sha256_hex),
        group_public_key: write.group_public_key,
        verification_shares_digest: write.verification_shares_json.map(sha256_hex),
        store_uuid: &write.source_fence.store_uuid,
        store_lease_id: &write.source_fence.lease_id,
        store_owner_epoch: write.source_fence.owner_epoch,
        updated_at_unix_ms: write.updated_at_unix_ms,
        completed_at_unix_ms: write.completed_at_unix_ms,
    };
    prefixed_digest(RECORD_DIGEST_PREFIX, &preimage)
}

fn custody_aad(purpose: &str, binding: &CustodyBinding<'_>) -> Result<Vec<u8>, FrostStoreError> {
    canonical_json_bytes(&CustodyAad {
        format: CUSTODY_AAD_FORMAT,
        purpose,
        ceremony_id: binding.ceremony_id,
        config_digest: binding.config_digest,
        state: binding.state,
        state_version: binding.state_version,
        custody_generation: binding.custody_generation,
        store_uuid: &binding.fence.store_uuid,
        store_lease_id: &binding.fence.lease_id,
        store_owner_epoch: binding.fence.owner_epoch,
        updated_at_unix_ms: binding.updated_at_unix_ms,
    })
    .map_err(|error| FrostStoreError::InvalidState(error.to_string()))
}

fn encrypt_material(
    plaintext: &[u8],
    custody: &FrostCustodyKey,
    aad: &[u8],
) -> Result<EncryptedBlob, FrostStoreError> {
    try_encrypt_blob_with_aad(custody.key(), plaintext, aad)
        .map_err(|_| FrostStoreError::Custody("ceremony material encryption failed"))
}

fn verify_custody_generation(
    stored: &StoredCeremonyRow,
    custody: &FrostCustodyKey,
) -> Result<(), FrostStoreError> {
    if stored.custody_generation != custody.generation() {
        return Err(FrostStoreError::Custody(
            "custody generation does not match the ceremony",
        ));
    }
    Ok(())
}

fn parse_secret_kind(value: &str) -> Result<FrostCeremonySecretKind, FrostStoreError> {
    match value {
        "round1" => Ok(FrostCeremonySecretKind::Round1),
        "round2" => Ok(FrostCeremonySecretKind::Round2),
        "key_package" => Ok(FrostCeremonySecretKind::KeyPackage),
        _ => Err(invalid("ceremony secret kind is unknown")),
    }
}

fn projection_key(ceremony_id: &str) -> String {
    format!("ceremony/{ceremony_id}")
}

fn validate_trusted_time(value: u64) -> Result<(), FrostStoreError> {
    if value == 0 || i64::try_from(value).is_err() {
        return Err(FrostStoreError::Conflict(
            "trusted time is outside the SQLite range",
        ));
    }
    Ok(())
}

fn nonce_from_row(row: &Row<'_>, index: usize) -> Result<[u8; 12], rusqlite::Error> {
    nonce_from_bytes(row.get(index)?, index)
}

fn nonce_from_bytes(bytes: Vec<u8>, index: usize) -> Result<[u8; 12], rusqlite::Error> {
    let length = bytes.len();
    bytes.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Blob,
            format!("FROST nonce must be 12 bytes, got {length}").into(),
        )
    })
}

fn sqlite_read_u64(row: &Row<'_>, index: usize) -> Result<u64, rusqlite::Error> {
    let value = row.get::<_, i64>(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

fn sqlite_u64(value: u64, field: &'static str) -> Result<i64, FrostStoreError> {
    i64::try_from(value)
        .map_err(|_| FrostStoreError::InvalidState(format!("{field} exceeds SQLite range")))
}

fn read_u64(value: i64, field: &'static str) -> Result<u64, FrostStoreError> {
    u64::try_from(value).map_err(|_| FrostStoreError::InvalidState(format!("{field} is negative")))
}

fn invalid(detail: impl Into<String>) -> FrostStoreError {
    FrostStoreError::InvalidState(detail.into())
}
