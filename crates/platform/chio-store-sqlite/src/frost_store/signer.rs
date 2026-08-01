use chio_core::canonical::canonical_json_bytes;
use chio_core::{sha256_hex, StoreMutationFence};
use chio_federation::frost::{
    frost_authorization_session_id, frost_authorization_slot_id,
    verify_bound_frost_authorization_slot, verify_burned_frost_authorization_slot,
    verify_completed_frost_authorization_slot, verify_frost_authorization_slot_bind,
    verify_frost_authorization_slot_burn, FrostAuthorizationSlotCheckpointV1,
    FrostAuthorizationSlotState,
};
use chio_federation_authority::{
    create_frost_signature_share, inspect_frost_signer_key, prepare_frost_signer,
    FrostCeremonySecret, FrostSignerNonceSecret,
};
use rand_core::{CryptoRng, RngCore};
use rusqlite::{Connection, OptionalExtension, Row};
use serde::Serialize;
use zeroize::Zeroizing;

use super::{
    FrostCeremonyState, FrostCustodyKey, FrostSignerCommitment, FrostSignerSessionRecord,
    FrostSignerSessionRequest, FrostSignerSessionState, FrostSignerShare, FrostStoreError,
    SqliteFrostStore,
};
use crate::encrypted_blob::{decrypt_blob_with_aad, try_encrypt_blob_with_aad, EncryptedBlob};

mod persistence;

use persistence::{
    append_signer_commit, insert_signer, load_signer_by_slot_query, load_signer_query,
    signer_record_digest, update_signer,
};

const SIGNER_RECORD_PREFIX: &[u8] = b"chio.frost.signer-record.digest.v1\0";
const SIGNER_AAD_FORMAT: &str = "chio.frost.signer-nonce-aad.v1";
const MAX_SIGNING_PACKAGE_BYTES: usize = 1024 * 1024;
const MAX_BURN_REASON_BYTES: usize = 256;

#[derive(Debug)]
struct ValidatedRequest {
    session_id: String,
    authorization_slot_id: String,
    authorization_body_json: Vec<u8>,
    signing_message_digest: String,
}

#[derive(Debug, Clone)]
struct StoredSigner {
    session_id: String,
    participant_id: String,
    authorization_slot_id: String,
    scope_id: String,
    key_epoch: u64,
    authorization_id: String,
    signing_message_digest: String,
    roster_digest: String,
    coordinator_id: String,
    resource_fence: u64,
    ceremony_id: String,
    authorization_body_json: Vec<u8>,
    bound_checkpoint_digest: String,
    bound_checkpoint_json: Vec<u8>,
    signer_identifier: Vec<u8>,
    verification_share: String,
    state: FrostSignerSessionState,
    state_version: u64,
    custody_generation: String,
    nonce_aad: Vec<u8>,
    nonce: Option<EncryptedBlob>,
    commitment_bytes: Vec<u8>,
    commitment_digest: String,
    signing_package_digest: Option<String>,
    signature_share: Option<Vec<u8>>,
    burn_reason: Option<String>,
    source_fence: StoreMutationFence,
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
    record_digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignerNonceAad<'a> {
    format: &'static str,
    participant_id: &'a str,
    scope_id: &'a str,
    key_epoch: u64,
    session_id: &'a str,
    authorization_id: &'a str,
    signing_message_digest: &'a str,
    coordinator_id: &'a str,
    resource_fence: u64,
    store_uuid: &'a str,
    store_lease_id: &'a str,
    store_owner_epoch: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignerRecordPreimage<'a> {
    format: &'static str,
    session_id: &'a str,
    participant_id: &'a str,
    authorization_slot_id: &'a str,
    scope_id: &'a str,
    key_epoch: u64,
    authorization_id: &'a str,
    signing_message_digest: &'a str,
    roster_digest: &'a str,
    coordinator_id: &'a str,
    resource_fence: u64,
    ceremony_id: &'a str,
    authorization_body_json_digest: String,
    bound_checkpoint_digest: &'a str,
    bound_checkpoint_json_digest: String,
    signer_identifier: String,
    verification_share: &'a str,
    state: FrostSignerSessionState,
    state_version: u64,
    custody_generation: &'a str,
    nonce_aad_digest: String,
    nonce_ciphertext_digest: Option<String>,
    nonce_nonce: Option<String>,
    commitment_digest: String,
    signing_package_digest: Option<&'a str>,
    signature_share_digest: Option<String>,
    burn_reason: Option<&'a str>,
    source_store_uuid: &'a str,
    source_lease_id: &'a str,
    source_owner_epoch: u64,
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
}

impl SqliteFrostStore {
    pub fn prepare_signer_session<R: CryptoRng + RngCore>(
        &self,
        request: &FrostSignerSessionRequest<'_>,
        custody: &FrostCustodyKey,
        rng: &mut R,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<FrostSignerSessionRecord, FrostStoreError> {
        validate_time(trusted_now_unix_ms)?;
        let validated = validate_request(request)?;
        if let Some(mut stored) = self.load_signer_by_slot(
            &validated.authorization_slot_id,
            request.participant_id,
            Some(fence),
        )? {
            if !matches_request(&stored, request, &validated) {
                self.burn_stored(
                    stored,
                    request,
                    fence,
                    trusted_now_unix_ms,
                    "signer input changed after slot binding",
                )?;
                return Err(FrostStoreError::Conflict(
                    "signer input changed after slot binding",
                ));
            }
            verify_custody(&stored, custody)?;
            verify_active_request(request)?;
            self.ensure_stored_slot_bound(request, &mut stored, fence, trusted_now_unix_ms)?;
            return Ok(public_record(&stored));
        }

        verify_active_request(request)?;
        let key_package = self.load_signer_key_package(request, custody, fence)?;
        let expected_share = request
            .active_roster
            .participant_verification_share(request.participant_id)
            .ok_or(FrostStoreError::Conflict(
                "signer participant is absent from the active roster",
            ))?;
        let key_identity =
            inspect_frost_signer_key(&key_package).map_err(|error| invalid(error.to_string()))?;
        if key_identity.verification_share() != expected_share {
            return Err(FrostStoreError::Conflict(
                "local key package does not match the active roster",
            ));
        }
        let bind = verify_frost_authorization_slot_bind(
            request.body,
            request.active_roster,
            request.epoch_anchor,
            request.artifact_trust,
            trusted_now_unix_ms,
        )
        .map_err(transition_error)?;
        let anchored = request
            .slot_anchor
            .compare_and_swap_bind(&bind)
            .map_err(anchor_error)?;
        let bound = verify_bound_frost_authorization_slot(
            request.body,
            request.active_roster,
            request.epoch_anchor,
            &anchored,
            request.artifact_trust,
            trusted_now_unix_ms,
        )
        .map_err(transition_error)?;
        let preparation = prepare_frost_signer(&key_package, rng)
            .map_err(|error| FrostStoreError::InvalidState(error.to_string()))?;
        if preparation.verification_share() != expected_share {
            return Err(FrostStoreError::Conflict(
                "local key package does not match the active roster",
            ));
        }
        let bound_checkpoint_json =
            canonical_json_bytes(bound.checkpoint()).map_err(|error| invalid(error.to_string()))?;
        let nonce_aad = signer_nonce_aad(request, &validated, fence)?;
        let nonce = try_encrypt_blob_with_aad(
            custody.key(),
            preparation.nonce_secret().custody_bytes(),
            &nonce_aad,
        )
        .map_err(|()| FrostStoreError::Custody("signer nonce encryption failed"))?;
        let mut stored = StoredSigner {
            session_id: validated.session_id,
            participant_id: request.participant_id.to_string(),
            authorization_slot_id: validated.authorization_slot_id,
            scope_id: request.body.scope_id.clone(),
            key_epoch: request.body.key_epoch,
            authorization_id: request.body.authorization_id.clone(),
            signing_message_digest: validated.signing_message_digest,
            roster_digest: request.body.roster_digest.clone(),
            coordinator_id: request.coordinator_id.to_string(),
            resource_fence: request.body.resource_fence,
            ceremony_id: request.ceremony_id.to_string(),
            authorization_body_json: validated.authorization_body_json,
            bound_checkpoint_digest: bound.checkpoint_digest().to_string(),
            bound_checkpoint_json,
            signer_identifier: preparation.signer_identifier_bytes().to_vec(),
            verification_share: preparation.verification_share().to_string(),
            state: FrostSignerSessionState::Prepared,
            state_version: 1,
            custody_generation: custody.generation().to_string(),
            nonce_aad,
            nonce: Some(nonce),
            commitment_bytes: preparation.commitment_bytes().to_vec(),
            commitment_digest: sha256_hex(preparation.commitment_bytes()),
            signing_package_digest: None,
            signature_share: None,
            burn_reason: None,
            source_fence: fence.clone(),
            created_at_unix_ms: trusted_now_unix_ms,
            updated_at_unix_ms: trusted_now_unix_ms,
            record_digest: String::new(),
        };
        stored.record_digest = signer_record_digest(&stored)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        if let Some(mut existing) = load_signer_by_slot_query(
            &transaction,
            &stored.authorization_slot_id,
            &stored.participant_id,
        )? {
            if matches_request(&existing, request, &validate_request(request)?) {
                transaction.commit().map_err(super::sqlite_error)?;
                drop(connection);
                verify_custody(&existing, custody)?;
                verify_active_request(request)?;
                self.ensure_stored_slot_bound(request, &mut existing, fence, trusted_now_unix_ms)?;
                return Ok(public_record(&existing));
            }
            return Err(FrostStoreError::Conflict(
                "another signer session claimed the authorization slot",
            ));
        }
        insert_signer(&transaction, &stored)?;
        append_signer_commit(&transaction, self, &stored, "frost.signer.prepare", fence)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(public_record(&stored))
    }

    pub fn publish_signer_commitment(
        &self,
        request: &FrostSignerSessionRequest<'_>,
        custody: &FrostCustodyKey,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<FrostSignerCommitment, FrostStoreError> {
        let mut stored = self.load_exact_live(request, fence, trusted_now_unix_ms)?;
        verify_custody(&stored, custody)?;
        if stored.state == FrostSignerSessionState::Prepared {
            let previous_state = stored.state;
            let previous_version = stored.state_version;
            stored.state = FrostSignerSessionState::CommitmentPublished;
            stored.state_version = 2;
            advance_record(&mut stored, fence, trusted_now_unix_ms)?;
            self.persist_transition(
                &stored,
                previous_state,
                previous_version,
                "frost.signer.publish_commitment",
                fence,
            )?;
        } else if !matches!(
            stored.state,
            FrostSignerSessionState::CommitmentPublished
                | FrostSignerSessionState::ShareReady
                | FrostSignerSessionState::Completed
        ) {
            return Err(FrostStoreError::Conflict(
                "signer commitment is unavailable in the current state",
            ));
        }
        Ok(public_commitment(&stored))
    }

    pub fn prepare_signer_share(
        &self,
        request: &FrostSignerSessionRequest<'_>,
        signing_package_bytes: &[u8],
        custody: &FrostCustodyKey,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<FrostSignerSessionRecord, FrostStoreError> {
        if signing_package_bytes.is_empty()
            || signing_package_bytes.len() > MAX_SIGNING_PACKAGE_BYTES
        {
            return Err(FrostStoreError::Conflict(
                "signing package length is outside the supported range",
            ));
        }
        let mut stored = self.load_exact_live(request, fence, trusted_now_unix_ms)?;
        verify_custody(&stored, custody)?;
        let package_digest = sha256_hex(signing_package_bytes);
        if matches!(
            stored.state,
            FrostSignerSessionState::ShareReady | FrostSignerSessionState::Completed
        ) {
            if stored.signing_package_digest.as_deref() == Some(package_digest.as_str()) {
                return Ok(public_record(&stored));
            }
            self.burn_stored(
                stored,
                request,
                fence,
                trusted_now_unix_ms,
                "signing package changed after share creation",
            )?;
            return Err(FrostStoreError::Conflict(
                "signing package changed after share creation",
            ));
        }
        if stored.state != FrostSignerSessionState::CommitmentPublished {
            return Err(FrostStoreError::Conflict(
                "signer commitment has not been published",
            ));
        }
        let nonce = stored
            .nonce
            .as_ref()
            .ok_or_else(|| invalid("live signer lacks encrypted nonce"))?;
        let nonce_plaintext = decrypt_blob_with_aad(custody.key(), nonce, &stored.nonce_aad)
            .map_err(|_| FrostStoreError::Custody("signer nonce authentication failed"))?;
        let nonce_secret =
            FrostSignerNonceSecret::from_custody_bytes(Zeroizing::new(nonce_plaintext))
                .map_err(|error| invalid(error.to_string()))?;
        let key_package = self.load_signer_key_package(request, custody, fence)?;
        let share = match create_frost_signature_share(
            &key_package,
            nonce_secret,
            signing_package_bytes,
            &stored.signing_message_digest,
            &stored.commitment_bytes,
        ) {
            Ok(share) => share,
            Err(error) => {
                let detail = error.to_string();
                self.burn_stored(
                    stored,
                    request,
                    fence,
                    trusted_now_unix_ms,
                    "signing package failed exact-message verification",
                )?;
                return Err(invalid(detail));
            }
        };
        let previous_state = stored.state;
        let previous_version = stored.state_version;
        stored.state = FrostSignerSessionState::ShareReady;
        stored.state_version = 3;
        stored.signing_package_digest = Some(package_digest);
        stored.signature_share = Some(share.share_bytes().to_vec());
        advance_record(&mut stored, fence, trusted_now_unix_ms)?;
        self.persist_transition(
            &stored,
            previous_state,
            previous_version,
            "frost.signer.prepare_share",
            fence,
        )?;
        Ok(public_record(&stored))
    }

    pub fn publish_signer_share(
        &self,
        request: &FrostSignerSessionRequest<'_>,
        custody: &FrostCustodyKey,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<FrostSignerShare, FrostStoreError> {
        let stored = self.load_exact_live(request, fence, trusted_now_unix_ms)?;
        verify_custody(&stored, custody)?;
        if !matches!(
            stored.state,
            FrostSignerSessionState::ShareReady | FrostSignerSessionState::Completed
        ) {
            return Err(FrostStoreError::Conflict(
                "signature share is unavailable in the current state",
            ));
        }
        let share_bytes = stored
            .signature_share
            .clone()
            .ok_or_else(|| invalid("share-ready signer lacks signature share"))?;
        Ok(FrostSignerShare {
            session_id: stored.session_id,
            participant_id: stored.participant_id,
            share_bytes,
        })
    }

    pub fn complete_signer_session(
        &self,
        request: &FrostSignerSessionRequest<'_>,
        custody: &FrostCustodyKey,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<FrostSignerSessionRecord, FrostStoreError> {
        let mut stored = self.load_exact_live(request, fence, trusted_now_unix_ms)?;
        verify_custody(&stored, custody)?;
        if stored.state == FrostSignerSessionState::Completed {
            return Ok(public_record(&stored));
        }
        if stored.state != FrostSignerSessionState::ShareReady {
            return Err(FrostStoreError::Conflict(
                "signer share is not ready for completion",
            ));
        }
        let previous_state = stored.state;
        let previous_version = stored.state_version;
        stored.state = FrostSignerSessionState::Completed;
        stored.state_version = 4;
        stored.nonce = None;
        advance_record(&mut stored, fence, trusted_now_unix_ms)?;
        self.persist_transition(
            &stored,
            previous_state,
            previous_version,
            "frost.signer.complete",
            fence,
        )?;
        Ok(public_record(&stored))
    }

    pub fn burn_signer_session(
        &self,
        request: &FrostSignerSessionRequest<'_>,
        reason: &str,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<FrostSignerSessionRecord, FrostStoreError> {
        let validated = validate_request(request)?;
        let stored = self
            .load_signer_by_slot(
                &validated.authorization_slot_id,
                request.participant_id,
                Some(fence),
            )?
            .ok_or(FrostStoreError::Conflict("signer session is absent"))?;
        if !matches_request(&stored, request, &validated) {
            return Err(FrostStoreError::Conflict(
                "burn request differs from the signer session",
            ));
        }
        self.burn_stored(stored, request, fence, trusted_now_unix_ms, reason)
    }

    pub fn load_signer_session(
        &self,
        session_id: &str,
        participant_id: &str,
    ) -> Result<Option<FrostSignerSessionRecord>, FrostStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection, None)?;
        let stored = load_signer_query(&transaction, session_id, participant_id)?;
        transaction.commit().map_err(super::sqlite_error)?;
        Ok(stored.as_ref().map(public_record))
    }

    fn load_exact_live(
        &self,
        request: &FrostSignerSessionRequest<'_>,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<StoredSigner, FrostStoreError> {
        validate_time(trusted_now_unix_ms)?;
        let validated = validate_request(request)?;
        let mut stored = self
            .load_signer_by_slot(
                &validated.authorization_slot_id,
                request.participant_id,
                Some(fence),
            )?
            .ok_or(FrostStoreError::Conflict("signer session is absent"))?;
        if !matches_request(&stored, request, &validated) {
            self.burn_stored(
                stored,
                request,
                fence,
                trusted_now_unix_ms,
                "signer input changed after slot binding",
            )?;
            return Err(FrostStoreError::Conflict(
                "signer input changed after slot binding",
            ));
        }
        if stored.state == FrostSignerSessionState::Burned {
            return Err(FrostStoreError::Conflict("signer session is burned"));
        }
        verify_active_request(request)?;
        self.ensure_stored_slot_bound(request, &mut stored, fence, trusted_now_unix_ms)?;
        Ok(stored)
    }

    fn ensure_stored_slot_bound(
        &self,
        request: &FrostSignerSessionRequest<'_>,
        stored: &mut StoredSigner,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(), FrostStoreError> {
        let slot_id = frost_authorization_slot_id(request.body)
            .map_err(|error| invalid(error.to_string()))?;
        let anchored = request
            .slot_anchor
            .resolve_authorization_slot(&request.body.scope_id, &slot_id)
            .map_err(anchor_error)?;
        match anchored.checkpoint.state {
            FrostAuthorizationSlotState::Bound => {
                let bound = verify_bound_frost_authorization_slot(
                    request.body,
                    request.active_roster,
                    request.epoch_anchor,
                    &anchored,
                    request.artifact_trust,
                    trusted_now_unix_ms,
                )
                .map_err(transition_error)?;
                if bound.checkpoint_digest() != stored.bound_checkpoint_digest {
                    return Err(FrostStoreError::Conflict(
                        "external bound checkpoint changed after signer preparation",
                    ));
                }
                Ok(())
            }
            FrostAuthorizationSlotState::Burned => {
                let bound: FrostAuthorizationSlotCheckpointV1 =
                    serde_json::from_slice(&stored.bound_checkpoint_json)
                        .map_err(|error| invalid(error.to_string()))?;
                verify_burned_frost_authorization_slot(
                    &bound,
                    &anchored,
                    request.artifact_trust,
                    trusted_now_unix_ms,
                )
                .map_err(transition_error)?;
                if !matches!(
                    stored.state,
                    FrostSignerSessionState::Completed | FrostSignerSessionState::Burned
                ) {
                    self.reconcile_local_burn(
                        stored,
                        fence,
                        trusted_now_unix_ms,
                        "external authorization slot was already burned",
                    )?;
                }
                Err(FrostStoreError::Conflict(
                    "external authorization slot is burned",
                ))
            }
            FrostAuthorizationSlotState::Completed => {
                verify_completed_frost_authorization_slot(
                    request.body,
                    request.active_roster,
                    request.epoch_anchor,
                    &anchored,
                    request.artifact_trust,
                    &stored.bound_checkpoint_digest,
                    trusted_now_unix_ms,
                )
                .map_err(transition_error)?;
                match stored.state {
                    FrostSignerSessionState::Completed => Ok(()),
                    FrostSignerSessionState::ShareReady => {
                        self.reconcile_local_completion(stored, fence, trusted_now_unix_ms)
                    }
                    FrostSignerSessionState::Prepared
                    | FrostSignerSessionState::CommitmentPublished => {
                        self.reconcile_local_burn(
                            stored,
                            fence,
                            trusted_now_unix_ms,
                            "external authorization completed without this signer share",
                        )?;
                        Err(FrostStoreError::Conflict(
                            "external authorization completed without this signer share",
                        ))
                    }
                    FrostSignerSessionState::Burned => {
                        Err(FrostStoreError::Conflict("signer session is burned"))
                    }
                }
            }
        }
    }

    fn load_signer_key_package(
        &self,
        request: &FrostSignerSessionRequest<'_>,
        custody: &FrostCustodyKey,
        fence: &StoreMutationFence,
    ) -> Result<FrostCeremonySecret, FrostStoreError> {
        let ceremony = self
            .load_ceremony(request.ceremony_id, custody)?
            .ok_or(FrostStoreError::Conflict("signer ceremony is absent"))?;
        if ceremony.state != FrostCeremonyState::Completed
            || ceremony.scope_id != request.body.scope_id
            || ceremony.key_epoch != request.body.key_epoch
            || ceremony.local_participant_id != request.participant_id
        {
            return Err(FrostStoreError::Conflict(
                "signer ceremony does not match the authorization",
            ));
        }
        self.load_completed_key_package(request.ceremony_id, custody, fence)
    }

    fn load_signer_by_slot(
        &self,
        slot_id: &str,
        participant_id: &str,
        fence: Option<&StoreMutationFence>,
    ) -> Result<Option<StoredSigner>, FrostStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection, fence)?;
        let stored = load_signer_by_slot_query(&transaction, slot_id, participant_id)?;
        transaction.commit().map_err(super::sqlite_error)?;
        Ok(stored)
    }

    fn persist_transition(
        &self,
        stored: &StoredSigner,
        previous_state: FrostSignerSessionState,
        previous_version: u64,
        mutation_kind: &str,
        fence: &StoreMutationFence,
    ) -> Result<(), FrostStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        update_signer(&transaction, stored, previous_state, previous_version)?;
        append_signer_commit(&transaction, self, stored, mutation_kind, fence)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)
    }

    fn burn_stored(
        &self,
        mut stored: StoredSigner,
        request: &FrostSignerSessionRequest<'_>,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
        reason: &str,
    ) -> Result<FrostSignerSessionRecord, FrostStoreError> {
        validate_burn_reason(reason)?;
        if stored.state == FrostSignerSessionState::Burned {
            return Ok(public_record(&stored));
        }
        if stored.state == FrostSignerSessionState::Completed {
            return Err(FrostStoreError::Conflict(
                "completed signer session cannot be burned",
            ));
        }
        let bound: FrostAuthorizationSlotCheckpointV1 =
            serde_json::from_slice(&stored.bound_checkpoint_json)
                .map_err(|error| invalid(error.to_string()))?;
        let burn = verify_frost_authorization_slot_burn(
            &bound,
            request.artifact_trust,
            trusted_now_unix_ms,
        )
        .map_err(transition_error)?;
        let anchored = request
            .slot_anchor
            .compare_and_swap_burn(&burn)
            .map_err(anchor_error)?;
        verify_burned_frost_authorization_slot(
            &bound,
            &anchored,
            request.artifact_trust,
            trusted_now_unix_ms,
        )
        .map_err(transition_error)?;
        let previous_state = stored.state;
        let previous_version = stored.state_version;
        stored.state = FrostSignerSessionState::Burned;
        stored.state_version = previous_version
            .checked_add(1)
            .ok_or_else(|| invalid("signer state version overflow"))?;
        stored.nonce = None;
        stored.signature_share = None;
        stored.burn_reason = Some(reason.to_string());
        advance_record(&mut stored, fence, trusted_now_unix_ms)?;
        self.persist_transition(
            &stored,
            previous_state,
            previous_version,
            "frost.signer.burn",
            fence,
        )?;
        Ok(public_record(&stored))
    }

    fn reconcile_local_burn(
        &self,
        stored: &mut StoredSigner,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
        reason: &str,
    ) -> Result<(), FrostStoreError> {
        validate_burn_reason(reason)?;
        let previous_state = stored.state;
        let previous_version = stored.state_version;
        stored.state = FrostSignerSessionState::Burned;
        stored.state_version = previous_version
            .checked_add(1)
            .ok_or_else(|| invalid("signer state version overflow"))?;
        stored.nonce = None;
        stored.signature_share = None;
        stored.burn_reason = Some(reason.to_string());
        advance_record(stored, fence, trusted_now_unix_ms)?;
        self.persist_transition(
            stored,
            previous_state,
            previous_version,
            "frost.signer.reconcile_burn",
            fence,
        )
    }

    fn reconcile_local_completion(
        &self,
        stored: &mut StoredSigner,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(), FrostStoreError> {
        let previous_state = stored.state;
        let previous_version = stored.state_version;
        stored.state = FrostSignerSessionState::Completed;
        stored.state_version = 4;
        stored.nonce = None;
        advance_record(stored, fence, trusted_now_unix_ms)?;
        self.persist_transition(
            stored,
            previous_state,
            previous_version,
            "frost.signer.reconcile_completion",
            fence,
        )
    }
}

pub(super) fn verify_signer_invariants(connection: &Connection) -> Result<(), FrostStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT session_id, participant_id FROM frost_signer_sessions ORDER BY session_id, participant_id",
        )
        .map_err(super::sqlite_error)?;
    let keys = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(super::sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(super::sqlite_error)?;
    drop(statement);
    for (session_id, participant_id) in keys {
        let stored = load_signer_query(connection, &session_id, &participant_id)?
            .ok_or_else(|| invalid("signer session disappeared during verification"))?;
        if stored.commitment_digest != sha256_hex(&stored.commitment_bytes) {
            return Err(invalid("FROST signer commitment digest is invalid"));
        }
        if signer_record_digest(&stored)? != stored.record_digest {
            return Err(invalid("FROST signer record digest is invalid"));
        }
        let (sequence, digest) = connection
            .query_row(
                r#"
                SELECT projection_sequence, record_digest
                FROM frost_projection_commits
                WHERE projection_key = ?1
                ORDER BY projection_sequence DESC LIMIT 1
                "#,
                [signer_projection_key(&session_id, &participant_id)],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(super::sqlite_error)?
            .ok_or_else(|| invalid("signer session lacks a projection commit"))?;
        if read_u64(sequence, "signer projection sequence")? != stored.state_version
            || digest != stored.record_digest
        {
            return Err(invalid("signer session diverges from its projection head"));
        }
    }
    Ok(())
}

fn validate_request(
    request: &FrostSignerSessionRequest<'_>,
) -> Result<ValidatedRequest, FrostStoreError> {
    request
        .body
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    validate_identifier(request.ceremony_id, "ceremony id")?;
    validate_identifier(request.participant_id, "participant id")?;
    validate_identifier(request.coordinator_id, "coordinator id")?;
    let signing_bytes = request
        .body
        .signing_bytes()
        .map_err(|error| invalid(error.to_string()))?;
    Ok(ValidatedRequest {
        session_id: frost_authorization_session_id(request.body)
            .map_err(|error| invalid(error.to_string()))?,
        authorization_slot_id: frost_authorization_slot_id(request.body)
            .map_err(|error| invalid(error.to_string()))?,
        authorization_body_json: canonical_json_bytes(request.body)
            .map_err(|error| invalid(error.to_string()))?,
        signing_message_digest: sha256_hex(&signing_bytes),
    })
}

fn verify_active_request(request: &FrostSignerSessionRequest<'_>) -> Result<(), FrostStoreError> {
    if request.body.scope_id != request.active_roster.scope_id()
        || request.body.key_epoch != request.active_roster.key_epoch()
        || request.body.roster_digest != request.active_roster.roster_digest()
        || request
            .active_roster
            .participant_verification_share(request.participant_id)
            .is_none()
    {
        return Err(FrostStoreError::Conflict(
            "signer request does not use the active roster",
        ));
    }
    Ok(())
}

fn matches_request(
    stored: &StoredSigner,
    request: &FrostSignerSessionRequest<'_>,
    validated: &ValidatedRequest,
) -> bool {
    stored.session_id == validated.session_id
        && stored.authorization_slot_id == validated.authorization_slot_id
        && stored.scope_id == request.body.scope_id
        && stored.key_epoch == request.body.key_epoch
        && stored.authorization_id == request.body.authorization_id
        && stored.signing_message_digest == validated.signing_message_digest
        && stored.roster_digest == request.body.roster_digest
        && stored.coordinator_id == request.coordinator_id
        && stored.resource_fence == request.body.resource_fence
        && stored.ceremony_id == request.ceremony_id
        && stored.authorization_body_json == validated.authorization_body_json
        && stored.participant_id == request.participant_id
}

fn signer_nonce_aad(
    request: &FrostSignerSessionRequest<'_>,
    validated: &ValidatedRequest,
    fence: &StoreMutationFence,
) -> Result<Vec<u8>, FrostStoreError> {
    canonical_json_bytes(&SignerNonceAad {
        format: SIGNER_AAD_FORMAT,
        participant_id: request.participant_id,
        scope_id: &request.body.scope_id,
        key_epoch: request.body.key_epoch,
        session_id: &validated.session_id,
        authorization_id: &request.body.authorization_id,
        signing_message_digest: &validated.signing_message_digest,
        coordinator_id: request.coordinator_id,
        resource_fence: request.body.resource_fence,
        store_uuid: &fence.store_uuid,
        store_lease_id: &fence.lease_id,
        store_owner_epoch: fence.owner_epoch,
    })
    .map_err(|error| invalid(error.to_string()))
}

fn advance_record(
    stored: &mut StoredSigner,
    fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<(), FrostStoreError> {
    if trusted_now_unix_ms < stored.updated_at_unix_ms {
        return Err(FrostStoreError::Conflict(
            "trusted time regressed behind the signer session",
        ));
    }
    stored.source_fence = fence.clone();
    stored.updated_at_unix_ms = trusted_now_unix_ms;
    stored.record_digest = signer_record_digest(stored)?;
    Ok(())
}

fn public_record(stored: &StoredSigner) -> FrostSignerSessionRecord {
    FrostSignerSessionRecord {
        session_id: stored.session_id.clone(),
        participant_id: stored.participant_id.clone(),
        authorization_slot_id: stored.authorization_slot_id.clone(),
        state: stored.state,
        state_version: stored.state_version,
    }
}

fn public_commitment(stored: &StoredSigner) -> FrostSignerCommitment {
    FrostSignerCommitment {
        session_id: stored.session_id.clone(),
        participant_id: stored.participant_id.clone(),
        signer_identifier: stored.signer_identifier.clone(),
        commitment_bytes: stored.commitment_bytes.clone(),
    }
}

fn signer_projection_key(session_id: &str, participant_id: &str) -> String {
    format!("signer/{session_id}/{participant_id}")
}

fn verify_custody(stored: &StoredSigner, custody: &FrostCustodyKey) -> Result<(), FrostStoreError> {
    if stored.custody_generation != custody.generation() {
        return Err(FrostStoreError::Custody(
            "custody generation does not match the signer session",
        ));
    }
    Ok(())
}

fn validate_identifier(value: &str, _field: &'static str) -> Result<(), FrostStoreError> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(FrostStoreError::Conflict("signer identifier is invalid"));
    }
    Ok(())
}

fn validate_burn_reason(reason: &str) -> Result<(), FrostStoreError> {
    if reason.is_empty()
        || reason.len() > MAX_BURN_REASON_BYTES
        || reason.trim() != reason
        || reason.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(FrostStoreError::Conflict("signer burn reason is invalid"));
    }
    Ok(())
}

fn validate_time(value: u64) -> Result<(), FrostStoreError> {
    if value == 0 {
        return Err(FrostStoreError::Conflict(
            "trusted signer time must be non-zero",
        ));
    }
    Ok(())
}

fn transition_error(error: impl std::fmt::Display) -> FrostStoreError {
    invalid(error.to_string())
}

fn anchor_error(error: impl std::fmt::Display) -> FrostStoreError {
    FrostStoreError::Unavailable(error.to_string())
}

fn invalid(detail: impl Into<String>) -> FrostStoreError {
    FrostStoreError::InvalidState(detail.into())
}

fn sqlite_u64(value: u64, field: &'static str) -> Result<i64, FrostStoreError> {
    i64::try_from(value).map_err(|_| invalid(format!("{field} exceeds SQLite range")))
}

fn sqlite_read_u64(row: &Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value = row.get::<_, i64>(index)?;
    u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn read_u64(value: i64, field: &'static str) -> Result<u64, FrostStoreError> {
    u64::try_from(value).map_err(|_| invalid(format!("{field} is negative")))
}

fn to_sql_conversion(error: FrostStoreError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(16, rusqlite::types::Type::Text, Box::new(error))
}
