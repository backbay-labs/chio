use std::collections::{BTreeMap, BTreeSet};

use chio_core::canonical::canonical_json_bytes;
use chio_core::{sha256_hex, StoreMutationFence};
use chio_federation::frost::{
    verify_bound_frost_authorization_slot, verify_burned_frost_authorization_slot,
    verify_completed_frost_authorization_slot, verify_frost_authorization_slot_bind,
    verify_frost_authorization_slot_burn, verify_frost_authorization_slot_completion,
    FrostAuthorizationSlotCheckpointV1, FrostAuthorizationSlotState, FrostAuthorizationV1,
};
use chio_federation_authority::{
    aggregate_frost_authorization, build_frost_signing_package, validate_frost_signing_commitment,
    verify_frost_signature_share,
};
use serde::Serialize;

use super::{
    FrostCoordinatorCancellation, FrostCoordinatorCommitment, FrostCoordinatorLease,
    FrostCoordinatorSessionRecord, FrostCoordinatorSessionRequest, FrostCoordinatorSessionState,
    FrostCoordinatorShare, FrostCoordinatorSigningPackage, FrostStoreError, SqliteFrostStore,
};

mod persistence;
mod validation;

use persistence::{
    append_coordinator_commit, insert_coordinator, load_coordinator_by_slot_query,
    load_coordinator_query, update_coordinator,
};
use validation::{
    ensure_live_state, matches_request, validate_lease, validate_request, verify_active_request,
    verify_lease,
};

const COORDINATOR_RECORD_PREFIX: &[u8] = b"chio.frost.coordinator-record.digest.v1\0";
const MAX_RUNTIME_IDENTIFIER_BYTES: usize = 128;
const MAX_LEASE_TTL_MS: u64 = 5 * 60 * 1_000;
const MAX_BURN_REASON_BYTES: usize = 256;
const MAX_AVAILABILITY_RECEIPT_BYTES: usize = 256;

pub(super) fn verify_coordinator_invariants(
    connection: &rusqlite::Connection,
) -> Result<(), FrostStoreError> {
    validation::verify_coordinator_invariants(connection)
}

#[derive(Debug)]
struct ValidatedRequest {
    session_id: String,
    authorization_slot_id: String,
    authorization_body_json: Vec<u8>,
    roster_json: Vec<u8>,
    signing_message_digest: String,
}

#[derive(Debug, Clone)]
struct StoredCoordinator {
    session_id: String,
    authorization_slot_id: String,
    scope_id: String,
    key_epoch: u64,
    authorization_id: String,
    signing_message_digest: String,
    roster_digest: String,
    coordinator_id: String,
    resource_fence: u64,
    authorization_body_json: Vec<u8>,
    roster_json: Vec<u8>,
    bound_checkpoint_digest: String,
    bound_checkpoint_json: Vec<u8>,
    state: FrostCoordinatorSessionState,
    row_version: u64,
    commitments: BTreeMap<String, Vec<u8>>,
    signing_participants: Option<Vec<String>>,
    signing_package: Option<Vec<u8>>,
    signing_package_digest: Option<String>,
    shares: BTreeMap<String, Vec<u8>>,
    authorization_blob: Option<Vec<u8>>,
    authorization_blob_digest: Option<String>,
    availability_receipt: Option<String>,
    burn_reason: Option<String>,
    coordinator_worker_id: String,
    coordinator_lease_id: String,
    coordinator_owner_epoch: u64,
    lease_expires_at_unix_ms: u64,
    source_fence: StoreMutationFence,
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
    record_digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CoordinatorRecordPreimage<'a> {
    format: &'static str,
    session_id: &'a str,
    authorization_slot_id: &'a str,
    scope_id: &'a str,
    key_epoch: u64,
    authorization_id: &'a str,
    signing_message_digest: &'a str,
    roster_digest: &'a str,
    coordinator_id: &'a str,
    resource_fence: u64,
    authorization_body_json_digest: String,
    roster_json_digest: String,
    bound_checkpoint_digest: &'a str,
    bound_checkpoint_json_digest: String,
    state: FrostCoordinatorSessionState,
    row_version: u64,
    commitments: BTreeMap<&'a str, String>,
    signing_participants: Option<&'a [String]>,
    signing_package_digest: Option<&'a str>,
    shares: BTreeMap<&'a str, String>,
    authorization_blob_digest: Option<&'a str>,
    availability_receipt: Option<&'a str>,
    burn_reason: Option<&'a str>,
    coordinator_worker_id: &'a str,
    coordinator_lease_id: &'a str,
    coordinator_owner_epoch: u64,
    lease_expires_at_unix_ms: u64,
    source_store_uuid: &'a str,
    source_lease_id: &'a str,
    source_owner_epoch: u64,
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
}

impl SqliteFrostStore {
    #[allow(clippy::too_many_arguments)]
    pub fn claim_coordinator_session(
        &self,
        request: &FrostCoordinatorSessionRequest<'_>,
        worker_id: &str,
        lease_id: &str,
        lease_ttl_ms: u64,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<FrostCoordinatorLease, FrostStoreError> {
        validate_time(trusted_now_unix_ms)?;
        validate_lease(worker_id, lease_id, lease_ttl_ms)?;
        let validated = validate_request(request)?;
        verify_active_request(request)?;
        if let Some(stored) =
            self.load_coordinator_by_slot(&validated.authorization_slot_id, Some(fence))?
        {
            if !matches_request(&stored, request, &validated) {
                let won_lease = self.claim_existing_lease(
                    stored.clone(),
                    worker_id,
                    lease_id,
                    lease_ttl_ms,
                    fence,
                    trusted_now_unix_ms,
                )?;
                let existing = self
                    .load_coordinator_by_slot(&validated.authorization_slot_id, Some(fence))?
                    .ok_or(FrostStoreError::Conflict("coordinator session is absent"))?;
                verify_lease(&existing, &won_lease, trusted_now_unix_ms)?;
                self.burn_conflicting_request(
                    existing,
                    request,
                    fence,
                    trusted_now_unix_ms,
                    "coordinator input changed after slot binding",
                )?;
                return Err(FrostStoreError::Conflict(
                    "coordinator input changed after slot binding",
                ));
            }
            return self.claim_and_reconcile_existing(
                stored,
                request,
                worker_id,
                lease_id,
                lease_ttl_ms,
                fence,
                trusted_now_unix_ms,
            );
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
        let expires_at = lease_expiry(trusted_now_unix_ms, lease_ttl_ms)?;
        let mut stored = StoredCoordinator {
            session_id: validated.session_id,
            authorization_slot_id: validated.authorization_slot_id,
            scope_id: request.body.scope_id.clone(),
            key_epoch: request.body.key_epoch,
            authorization_id: request.body.authorization_id.clone(),
            signing_message_digest: validated.signing_message_digest,
            roster_digest: request.body.roster_digest.clone(),
            coordinator_id: request.coordinator_id.to_string(),
            resource_fence: request.body.resource_fence,
            authorization_body_json: validated.authorization_body_json,
            roster_json: validated.roster_json,
            bound_checkpoint_digest: bound.checkpoint_digest().to_string(),
            bound_checkpoint_json: canonical_json_bytes(bound.checkpoint())
                .map_err(|error| invalid(error.to_string()))?,
            state: FrostCoordinatorSessionState::CollectingCommitments,
            row_version: 1,
            commitments: BTreeMap::new(),
            signing_participants: None,
            signing_package: None,
            signing_package_digest: None,
            shares: BTreeMap::new(),
            authorization_blob: None,
            authorization_blob_digest: None,
            availability_receipt: None,
            burn_reason: None,
            coordinator_worker_id: worker_id.to_string(),
            coordinator_lease_id: lease_id.to_string(),
            coordinator_owner_epoch: 1,
            lease_expires_at_unix_ms: expires_at,
            source_fence: fence.clone(),
            created_at_unix_ms: trusted_now_unix_ms,
            updated_at_unix_ms: trusted_now_unix_ms,
            record_digest: String::new(),
        };
        stored.record_digest = coordinator_record_digest(&stored)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        if let Some(existing) =
            load_coordinator_by_slot_query(&transaction, &stored.authorization_slot_id)?
        {
            transaction.commit().map_err(super::sqlite_error)?;
            drop(connection);
            if !matches_request(&existing, request, &validate_request(request)?) {
                return Err(FrostStoreError::Conflict(
                    "another coordinator session claimed the authorization slot",
                ));
            }
            return self.claim_and_reconcile_existing(
                existing,
                request,
                worker_id,
                lease_id,
                lease_ttl_ms,
                fence,
                trusted_now_unix_ms,
            );
        }
        insert_coordinator(&transaction, &stored)?;
        append_coordinator_commit(
            &transaction,
            self,
            &stored,
            "frost.coordinator.claim",
            fence,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(public_lease(&stored))
    }

    pub fn renew_coordinator_lease(
        &self,
        request: &FrostCoordinatorSessionRequest<'_>,
        lease: &FrostCoordinatorLease,
        lease_ttl_ms: u64,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<FrostCoordinatorLease, FrostStoreError> {
        validate_lease(&lease.worker_id, &lease.lease_id, lease_ttl_ms)?;
        let mut stored = self.load_exact(request, lease, fence, trusted_now_unix_ms)?;
        ensure_live_state(&stored)?;
        let expires_at = lease_expiry(trusted_now_unix_ms, lease_ttl_ms)?;
        if expires_at <= stored.lease_expires_at_unix_ms {
            return Err(FrostStoreError::Conflict(
                "coordinator lease renewal does not advance expiry",
            ));
        }
        let previous_version = stored.row_version;
        stored.lease_expires_at_unix_ms = expires_at;
        advance_record(&mut stored, fence, trusted_now_unix_ms)?;
        self.persist_coordinator_transition(
            &stored,
            previous_version,
            "frost.coordinator.renew_lease",
            fence,
        )?;
        Ok(public_lease(&stored))
    }

    pub fn submit_coordinator_commitment(
        &self,
        request: &FrostCoordinatorSessionRequest<'_>,
        lease: &FrostCoordinatorLease,
        commitment: &FrostCoordinatorCommitment,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<FrostCoordinatorSessionRecord, FrostStoreError> {
        let mut stored = self.load_exact(request, lease, fence, trusted_now_unix_ms)?;
        if stored.state != FrostCoordinatorSessionState::CollectingCommitments {
            return Err(FrostStoreError::Conflict(
                "coordinator commitment collection is closed",
            ));
        }
        validate_frost_signing_commitment(
            request.active_roster.roster(),
            &commitment.participant_id,
            &commitment.signer_identifier,
            &commitment.commitment_bytes,
        )
        .map_err(coordinator_error)?;
        if let Some(existing) = stored.commitments.get(&commitment.participant_id) {
            if existing == &commitment.commitment_bytes {
                return Ok(public_record(&stored));
            }
            return Err(FrostStoreError::Conflict(
                "participant commitment changed after publication",
            ));
        }
        if stored.commitments.len() >= usize::from(request.active_roster.roster().participant_count)
        {
            return Err(FrostStoreError::Conflict(
                "coordinator commitment set exceeds the roster",
            ));
        }
        let previous_version = stored.row_version;
        stored.commitments.insert(
            commitment.participant_id.clone(),
            commitment.commitment_bytes.clone(),
        );
        advance_record(&mut stored, fence, trusted_now_unix_ms)?;
        self.persist_coordinator_transition(
            &stored,
            previous_version,
            "frost.coordinator.accept_commitment",
            fence,
        )?;
        Ok(public_record(&stored))
    }

    pub fn build_coordinator_signing_package(
        &self,
        request: &FrostCoordinatorSessionRequest<'_>,
        lease: &FrostCoordinatorLease,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<FrostCoordinatorSigningPackage, FrostStoreError> {
        let mut stored = self.load_exact(request, lease, fence, trusted_now_unix_ms)?;
        if let Some(package) = public_signing_package(&stored)? {
            return Ok(package);
        }
        if stored.state != FrostCoordinatorSessionState::CollectingCommitments {
            return Err(FrostStoreError::Conflict(
                "coordinator signing package is unavailable",
            ));
        }
        let package = build_frost_signing_package(
            request.body,
            request.active_roster.roster(),
            &stored.commitments,
        )
        .map_err(coordinator_error)?;
        let previous_version = stored.row_version;
        stored.state = FrostCoordinatorSessionState::PackageReady;
        stored.signing_participants = Some(package.participant_ids().to_vec());
        stored.signing_package = Some(package.bytes().to_vec());
        stored.signing_package_digest = Some(sha256_hex(package.bytes()));
        advance_record(&mut stored, fence, trusted_now_unix_ms)?;
        self.persist_coordinator_transition(
            &stored,
            previous_version,
            "frost.coordinator.build_package",
            fence,
        )?;
        public_signing_package(&stored)?.ok_or_else(|| invalid("persisted package is absent"))
    }

    pub fn submit_coordinator_share(
        &self,
        request: &FrostCoordinatorSessionRequest<'_>,
        lease: &FrostCoordinatorLease,
        share: &FrostCoordinatorShare,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<FrostCoordinatorSessionRecord, FrostStoreError> {
        let mut stored = self.load_exact(request, lease, fence, trusted_now_unix_ms)?;
        if stored.state != FrostCoordinatorSessionState::PackageReady {
            return Err(FrostStoreError::Conflict(
                "coordinator is not accepting signature shares",
            ));
        }
        let participants = stored
            .signing_participants
            .as_ref()
            .ok_or_else(|| invalid("package-ready coordinator lacks participants"))?;
        if participants.binary_search(&share.participant_id).is_err() {
            return Err(FrostStoreError::Conflict(
                "signature share participant is outside the signing set",
            ));
        }
        let package = stored
            .signing_package
            .as_deref()
            .ok_or_else(|| invalid("package-ready coordinator lacks a package"))?;
        verify_frost_signature_share(
            request.body,
            request.active_roster.roster(),
            package,
            &share.participant_id,
            &share.share_bytes,
        )
        .map_err(coordinator_error)?;
        if let Some(existing) = stored.shares.get(&share.participant_id) {
            if existing == &share.share_bytes {
                return Ok(public_record(&stored));
            }
            return Err(FrostStoreError::Conflict(
                "participant signature share changed after publication",
            ));
        }
        let previous_version = stored.row_version;
        stored
            .shares
            .insert(share.participant_id.clone(), share.share_bytes.clone());
        advance_record(&mut stored, fence, trusted_now_unix_ms)?;
        self.persist_coordinator_transition(
            &stored,
            previous_version,
            "frost.coordinator.accept_share",
            fence,
        )?;
        Ok(public_record(&stored))
    }

    pub fn complete_coordinator_session(
        &self,
        request: &FrostCoordinatorSessionRequest<'_>,
        lease: &FrostCoordinatorLease,
        availability_receipt: &str,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<FrostAuthorizationV1, FrostStoreError> {
        validate_availability_receipt(availability_receipt)?;
        let mut stored = self.load_exact(request, lease, fence, trusted_now_unix_ms)?;
        if stored.state == FrostCoordinatorSessionState::Completed {
            return stored_authorization(&stored);
        }
        if stored.state == FrostCoordinatorSessionState::PackageReady {
            if stored.shares.len() < usize::from(request.active_roster.roster().threshold) {
                return Err(FrostStoreError::Conflict(
                    "coordinator signature shares do not satisfy the active roster threshold",
                ));
            }
            let package = stored
                .signing_package
                .as_deref()
                .ok_or_else(|| invalid("package-ready coordinator lacks a package"))?;
            let proof = aggregate_frost_authorization(
                request.body,
                request.active_roster.roster(),
                package,
                &stored.shares,
            )
            .map_err(coordinator_error)?;
            let bound = stored_bound_checkpoint(&stored)?;
            verify_frost_authorization_slot_completion(
                &bound,
                &proof,
                request.active_roster,
                request.epoch_anchor,
                request.artifact_trust,
                availability_receipt,
                trusted_now_unix_ms,
            )
            .map_err(transition_error)?;
            let blob = proof
                .canonical_bytes()
                .map_err(|error| invalid(error.to_string()))?;
            let previous_version = stored.row_version;
            stored.state = FrostCoordinatorSessionState::AuthorizationReady;
            stored.authorization_blob_digest = Some(sha256_hex(&blob));
            stored.authorization_blob = Some(blob);
            stored.availability_receipt = Some(availability_receipt.to_string());
            advance_record(&mut stored, fence, trusted_now_unix_ms)?;
            self.persist_coordinator_transition(
                &stored,
                previous_version,
                "frost.coordinator.aggregate",
                fence,
            )?;
        } else if stored.state != FrostCoordinatorSessionState::AuthorizationReady {
            return Err(FrostStoreError::Conflict(
                "coordinator authorization cannot be completed in the current state",
            ));
        }
        if stored.availability_receipt.as_deref() != Some(availability_receipt) {
            return Err(FrostStoreError::Conflict(
                "availability receipt changed after authorization aggregation",
            ));
        }
        let proof = stored_authorization(&stored)?;
        let bound = stored_bound_checkpoint(&stored)?;
        let completion = verify_frost_authorization_slot_completion(
            &bound,
            &proof,
            request.active_roster,
            request.epoch_anchor,
            request.artifact_trust,
            availability_receipt,
            trusted_now_unix_ms,
        )
        .map_err(transition_error)?;
        let anchored = request
            .slot_anchor
            .compare_and_swap_complete(&completion)
            .map_err(anchor_error)?;
        let completed = verify_completed_frost_authorization_slot(
            request.body,
            request.active_roster,
            request.epoch_anchor,
            &anchored,
            request.artifact_trust,
            &stored.bound_checkpoint_digest,
            trusted_now_unix_ms,
        )
        .map_err(transition_error)?;
        if completed.proof() != &proof {
            return Err(FrostStoreError::Conflict(
                "external completion differs from the persisted authorization",
            ));
        }
        let previous_version = stored.row_version;
        stored.state = FrostCoordinatorSessionState::Completed;
        advance_record(&mut stored, fence, trusted_now_unix_ms)?;
        self.persist_coordinator_transition(
            &stored,
            previous_version,
            "frost.coordinator.complete",
            fence,
        )?;
        Ok(proof)
    }

    pub fn cancel_coordinator_session(
        &self,
        request: &FrostCoordinatorSessionRequest<'_>,
        lease: &FrostCoordinatorLease,
        reason: &str,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<FrostCoordinatorCancellation, FrostStoreError> {
        validate_burn_reason(reason)?;
        let validated = validate_request(request)?;
        let mut stored = self
            .load_coordinator_by_slot(&validated.authorization_slot_id, Some(fence))?
            .ok_or(FrostStoreError::Conflict("coordinator session is absent"))?;
        if !matches_request(&stored, request, &validated) {
            return Err(FrostStoreError::Conflict(
                "cancellation differs from the coordinator session",
            ));
        }
        verify_lease(&stored, lease, trusted_now_unix_ms)?;
        if stored.state == FrostCoordinatorSessionState::Completed {
            return Err(FrostStoreError::Conflict(
                "completed coordinator session cannot be canceled",
            ));
        }
        let bound = stored_bound_checkpoint(&stored)?;
        let anchored = request
            .slot_anchor
            .resolve_authorization_slot(&stored.scope_id, &stored.authorization_slot_id)
            .map_err(anchor_error)?;
        if anchored.checkpoint.state == FrostAuthorizationSlotState::Completed {
            return Err(FrostStoreError::Conflict(
                "completed authorization slot cannot be canceled",
            ));
        }
        if anchored.checkpoint.state == FrostAuthorizationSlotState::Bound {
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
        } else {
            verify_burned_frost_authorization_slot(
                &bound,
                &anchored,
                request.artifact_trust,
                trusted_now_unix_ms,
            )
            .map_err(transition_error)?;
        }
        if stored.state != FrostCoordinatorSessionState::Burned {
            self.mark_burned(
                &mut stored,
                reason,
                fence,
                trusted_now_unix_ms,
                "frost.coordinator.cancel",
            )?;
        }
        Ok(public_cancellation(&stored))
    }

    pub fn load_coordinator_session(
        &self,
        session_id: &str,
    ) -> Result<Option<FrostCoordinatorSessionRecord>, FrostStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection, None)?;
        let stored = load_coordinator_query(&transaction, session_id)?;
        transaction.commit().map_err(super::sqlite_error)?;
        Ok(stored.as_ref().map(public_record))
    }

    fn claim_existing_lease(
        &self,
        mut stored: StoredCoordinator,
        worker_id: &str,
        lease_id: &str,
        lease_ttl_ms: u64,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<FrostCoordinatorLease, FrostStoreError> {
        if stored.coordinator_worker_id == worker_id
            && stored.coordinator_lease_id == lease_id
            && stored.lease_expires_at_unix_ms > trusted_now_unix_ms
        {
            return Ok(public_lease(&stored));
        }
        if stored.lease_expires_at_unix_ms > trusted_now_unix_ms {
            return Err(FrostStoreError::Conflict(
                "coordinator session is leased by another worker",
            ));
        }
        if stored.coordinator_worker_id == worker_id && stored.coordinator_lease_id == lease_id {
            return Err(FrostStoreError::Conflict(
                "expired coordinator lease must be replaced",
            ));
        }
        let previous_version = stored.row_version;
        stored.coordinator_worker_id = worker_id.to_string();
        stored.coordinator_lease_id = lease_id.to_string();
        stored.coordinator_owner_epoch = stored
            .coordinator_owner_epoch
            .checked_add(1)
            .ok_or_else(|| invalid("coordinator owner epoch overflow"))?;
        stored.lease_expires_at_unix_ms = lease_expiry(trusted_now_unix_ms, lease_ttl_ms)?;
        advance_record(&mut stored, fence, trusted_now_unix_ms)?;
        self.persist_coordinator_transition(
            &stored,
            previous_version,
            "frost.coordinator.takeover",
            fence,
        )?;
        Ok(public_lease(&stored))
    }

    #[allow(clippy::too_many_arguments)]
    fn claim_and_reconcile_existing(
        &self,
        stored: StoredCoordinator,
        request: &FrostCoordinatorSessionRequest<'_>,
        worker_id: &str,
        lease_id: &str,
        lease_ttl_ms: u64,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<FrostCoordinatorLease, FrostStoreError> {
        let lease = self.claim_existing_lease(
            stored,
            worker_id,
            lease_id,
            lease_ttl_ms,
            fence,
            trusted_now_unix_ms,
        )?;
        let stored = self
            .load_coordinator_by_slot(&lease.authorization_slot_id, Some(fence))?
            .ok_or(FrostStoreError::Conflict("coordinator session is absent"))?;
        verify_lease(&stored, &lease, trusted_now_unix_ms)?;
        self.reconcile_external(stored, request, fence, trusted_now_unix_ms)?;
        Ok(lease)
    }

    fn load_exact(
        &self,
        request: &FrostCoordinatorSessionRequest<'_>,
        lease: &FrostCoordinatorLease,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<StoredCoordinator, FrostStoreError> {
        validate_time(trusted_now_unix_ms)?;
        let validated = validate_request(request)?;
        let stored = self
            .load_coordinator_by_slot(&validated.authorization_slot_id, Some(fence))?
            .ok_or(FrostStoreError::Conflict("coordinator session is absent"))?;
        if !matches_request(&stored, request, &validated) {
            return Err(FrostStoreError::Conflict(
                "request differs from the coordinator session",
            ));
        }
        verify_lease(&stored, lease, trusted_now_unix_ms)?;
        verify_active_request(request)?;
        self.reconcile_external(stored, request, fence, trusted_now_unix_ms)
    }

    fn reconcile_external(
        &self,
        mut stored: StoredCoordinator,
        request: &FrostCoordinatorSessionRequest<'_>,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<StoredCoordinator, FrostStoreError> {
        let anchored = request
            .slot_anchor
            .resolve_authorization_slot(&stored.scope_id, &stored.authorization_slot_id)
            .map_err(anchor_error)?;
        let bound = stored_bound_checkpoint(&stored)?;
        match anchored.checkpoint.state {
            FrostAuthorizationSlotState::Bound => {
                let verified = verify_bound_frost_authorization_slot(
                    request.body,
                    request.active_roster,
                    request.epoch_anchor,
                    &anchored,
                    request.artifact_trust,
                    trusted_now_unix_ms,
                )
                .map_err(transition_error)?;
                if verified.checkpoint_digest() != stored.bound_checkpoint_digest {
                    return Err(FrostStoreError::Conflict(
                        "external bound checkpoint changed after coordinator claim",
                    ));
                }
                if matches!(
                    stored.state,
                    FrostCoordinatorSessionState::Completed | FrostCoordinatorSessionState::Burned
                ) {
                    return Err(invalid(
                        "terminal coordinator session has a nonterminal external slot",
                    ));
                }
            }
            FrostAuthorizationSlotState::Burned => {
                verify_burned_frost_authorization_slot(
                    &bound,
                    &anchored,
                    request.artifact_trust,
                    trusted_now_unix_ms,
                )
                .map_err(transition_error)?;
                if stored.state == FrostCoordinatorSessionState::Completed {
                    return Err(invalid(
                        "completed coordinator session has a burned external slot",
                    ));
                }
                if stored.state != FrostCoordinatorSessionState::Burned {
                    self.mark_burned(
                        &mut stored,
                        "external authorization slot was already burned",
                        fence,
                        trusted_now_unix_ms,
                        "frost.coordinator.reconcile_burn",
                    )?;
                }
            }
            FrostAuthorizationSlotState::Completed => {
                let completed = verify_completed_frost_authorization_slot(
                    request.body,
                    request.active_roster,
                    request.epoch_anchor,
                    &anchored,
                    request.artifact_trust,
                    &stored.bound_checkpoint_digest,
                    trusted_now_unix_ms,
                )
                .map_err(transition_error)?;
                let blob = completed
                    .proof()
                    .canonical_bytes()
                    .map_err(|error| invalid(error.to_string()))?;
                match stored.state {
                    FrostCoordinatorSessionState::AuthorizationReady
                    | FrostCoordinatorSessionState::Completed => {
                        if stored.authorization_blob.as_deref() != Some(blob.as_slice()) {
                            return Err(FrostStoreError::Conflict(
                                "external authorization differs from the local aggregate",
                            ));
                        }
                    }
                    FrostCoordinatorSessionState::PackageReady => {
                        let package = stored.signing_package.as_deref().ok_or_else(|| {
                            invalid("package-ready coordinator lacks a signing package")
                        })?;
                        let expected = aggregate_frost_authorization(
                            request.body,
                            request.active_roster.roster(),
                            package,
                            &stored.shares,
                        )
                        .map_err(coordinator_error)?;
                        if expected != *completed.proof() {
                            return Err(FrostStoreError::Conflict(
                                "external authorization differs from the persisted shares",
                            ));
                        }
                        stored.authorization_blob_digest = Some(sha256_hex(&blob));
                        stored.authorization_blob = Some(blob);
                        stored.availability_receipt =
                            completed.checkpoint().availability_receipt.clone();
                    }
                    FrostCoordinatorSessionState::CollectingCommitments => {
                        return Err(invalid(
                            "external completion predates the persisted signing package",
                        ));
                    }
                    FrostCoordinatorSessionState::Burned => {
                        return Err(invalid(
                            "burned coordinator session has a completed external slot",
                        ));
                    }
                }
                if stored.state != FrostCoordinatorSessionState::Completed {
                    let previous_version = stored.row_version;
                    stored.state = FrostCoordinatorSessionState::Completed;
                    advance_record(&mut stored, fence, trusted_now_unix_ms)?;
                    self.persist_coordinator_transition(
                        &stored,
                        previous_version,
                        "frost.coordinator.reconcile_completion",
                        fence,
                    )?;
                }
            }
        }
        Ok(stored)
    }

    fn burn_conflicting_request(
        &self,
        mut stored: StoredCoordinator,
        request: &FrostCoordinatorSessionRequest<'_>,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
        reason: &str,
    ) -> Result<(), FrostStoreError> {
        if stored.coordinator_id != request.coordinator_id {
            return Err(FrostStoreError::Conflict(
                "coordinator identity differs from the claimed session",
            ));
        }
        if stored.state == FrostCoordinatorSessionState::Completed {
            return Err(FrostStoreError::Conflict(
                "completed coordinator session cannot be burned",
            ));
        }
        let bound = stored_bound_checkpoint(&stored)?;
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
        if stored.state != FrostCoordinatorSessionState::Burned {
            self.mark_burned(
                &mut stored,
                reason,
                fence,
                trusted_now_unix_ms,
                "frost.coordinator.burn_conflict",
            )?;
        }
        Ok(())
    }

    fn mark_burned(
        &self,
        stored: &mut StoredCoordinator,
        reason: &str,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
        mutation_kind: &str,
    ) -> Result<(), FrostStoreError> {
        validate_burn_reason(reason)?;
        let previous_version = stored.row_version;
        stored.state = FrostCoordinatorSessionState::Burned;
        stored.burn_reason = Some(reason.to_string());
        advance_record(stored, fence, trusted_now_unix_ms)?;
        self.persist_coordinator_transition(stored, previous_version, mutation_kind, fence)
    }

    fn load_coordinator_by_slot(
        &self,
        slot_id: &str,
        fence: Option<&StoreMutationFence>,
    ) -> Result<Option<StoredCoordinator>, FrostStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection, fence)?;
        let stored = load_coordinator_by_slot_query(&transaction, slot_id)?;
        transaction.commit().map_err(super::sqlite_error)?;
        Ok(stored)
    }

    fn persist_coordinator_transition(
        &self,
        stored: &StoredCoordinator,
        previous_version: u64,
        mutation_kind: &str,
        fence: &StoreMutationFence,
    ) -> Result<(), FrostStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        update_coordinator(&transaction, stored, previous_version)?;
        append_coordinator_commit(&transaction, self, stored, mutation_kind, fence)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)
    }
}

fn advance_record(
    stored: &mut StoredCoordinator,
    fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<(), FrostStoreError> {
    if trusted_now_unix_ms < stored.updated_at_unix_ms {
        return Err(FrostStoreError::Conflict(
            "trusted time regressed behind the coordinator session",
        ));
    }
    stored.row_version = stored
        .row_version
        .checked_add(1)
        .ok_or_else(|| invalid("coordinator row version overflow"))?;
    stored.source_fence = fence.clone();
    stored.updated_at_unix_ms = trusted_now_unix_ms;
    stored.record_digest = coordinator_record_digest(stored)?;
    Ok(())
}

fn stored_bound_checkpoint(
    stored: &StoredCoordinator,
) -> Result<FrostAuthorizationSlotCheckpointV1, FrostStoreError> {
    serde_json::from_slice(&stored.bound_checkpoint_json)
        .map_err(|error| invalid(error.to_string()))
}

fn stored_authorization(
    stored: &StoredCoordinator,
) -> Result<FrostAuthorizationV1, FrostStoreError> {
    serde_json::from_slice(
        stored
            .authorization_blob
            .as_deref()
            .ok_or_else(|| invalid("coordinator authorization bytes are absent"))?,
    )
    .map_err(|error| invalid(error.to_string()))
}

fn public_record(stored: &StoredCoordinator) -> FrostCoordinatorSessionRecord {
    FrostCoordinatorSessionRecord {
        session_id: stored.session_id.clone(),
        authorization_slot_id: stored.authorization_slot_id.clone(),
        state: stored.state,
        row_version: stored.row_version,
        commitment_count: stored.commitments.len(),
        share_count: stored.shares.len(),
    }
}

fn public_lease(stored: &StoredCoordinator) -> FrostCoordinatorLease {
    FrostCoordinatorLease {
        session_id: stored.session_id.clone(),
        authorization_slot_id: stored.authorization_slot_id.clone(),
        coordinator_id: stored.coordinator_id.clone(),
        worker_id: stored.coordinator_worker_id.clone(),
        lease_id: stored.coordinator_lease_id.clone(),
        owner_epoch: stored.coordinator_owner_epoch,
        expires_at_unix_ms: stored.lease_expires_at_unix_ms,
    }
}

fn public_signing_package(
    stored: &StoredCoordinator,
) -> Result<Option<FrostCoordinatorSigningPackage>, FrostStoreError> {
    match (
        stored.signing_participants.as_ref(),
        stored.signing_package.as_ref(),
    ) {
        (Some(participant_ids), Some(bytes)) => Ok(Some(FrostCoordinatorSigningPackage {
            session_id: stored.session_id.clone(),
            participant_ids: participant_ids.clone(),
            signing_package_bytes: bytes.clone(),
        })),
        (None, None) => Ok(None),
        _ => Err(invalid("coordinator signing package is partially stored")),
    }
}

fn public_cancellation(stored: &StoredCoordinator) -> FrostCoordinatorCancellation {
    let participant_ids = stored
        .commitments
        .keys()
        .chain(stored.shares.keys())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    FrostCoordinatorCancellation {
        session: public_record(stored),
        participant_ids,
    }
}

fn coordinator_record_digest(stored: &StoredCoordinator) -> Result<String, FrostStoreError> {
    persistence::prefixed_coordinator_digest(
        COORDINATOR_RECORD_PREFIX,
        &CoordinatorRecordPreimage {
            format: "chio.frost.coordinator-record.v1",
            session_id: &stored.session_id,
            authorization_slot_id: &stored.authorization_slot_id,
            scope_id: &stored.scope_id,
            key_epoch: stored.key_epoch,
            authorization_id: &stored.authorization_id,
            signing_message_digest: &stored.signing_message_digest,
            roster_digest: &stored.roster_digest,
            coordinator_id: &stored.coordinator_id,
            resource_fence: stored.resource_fence,
            authorization_body_json_digest: sha256_hex(&stored.authorization_body_json),
            roster_json_digest: sha256_hex(&stored.roster_json),
            bound_checkpoint_digest: &stored.bound_checkpoint_digest,
            bound_checkpoint_json_digest: sha256_hex(&stored.bound_checkpoint_json),
            state: stored.state,
            row_version: stored.row_version,
            commitments: stored
                .commitments
                .iter()
                .map(|(participant, bytes)| (participant.as_str(), hex::encode(bytes)))
                .collect(),
            signing_participants: stored.signing_participants.as_deref(),
            signing_package_digest: stored.signing_package_digest.as_deref(),
            shares: stored
                .shares
                .iter()
                .map(|(participant, bytes)| (participant.as_str(), hex::encode(bytes)))
                .collect(),
            authorization_blob_digest: stored.authorization_blob_digest.as_deref(),
            availability_receipt: stored.availability_receipt.as_deref(),
            burn_reason: stored.burn_reason.as_deref(),
            coordinator_worker_id: &stored.coordinator_worker_id,
            coordinator_lease_id: &stored.coordinator_lease_id,
            coordinator_owner_epoch: stored.coordinator_owner_epoch,
            lease_expires_at_unix_ms: stored.lease_expires_at_unix_ms,
            source_store_uuid: &stored.source_fence.store_uuid,
            source_lease_id: &stored.source_fence.lease_id,
            source_owner_epoch: stored.source_fence.owner_epoch,
            created_at_unix_ms: stored.created_at_unix_ms,
            updated_at_unix_ms: stored.updated_at_unix_ms,
        },
    )
}

fn coordinator_projection_key(session_id: &str) -> String {
    format!("coordinator/{session_id}")
}

fn validate_time(trusted_now_unix_ms: u64) -> Result<(), FrostStoreError> {
    if trusted_now_unix_ms == 0 {
        Err(FrostStoreError::InvalidState(
            "trusted time must be positive".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn lease_expiry(now: u64, ttl: u64) -> Result<u64, FrostStoreError> {
    now.checked_add(ttl)
        .ok_or_else(|| invalid("coordinator lease expiry overflow"))
}

/// Rejects the same reasons the signer store rejects, so a reason durably burned
/// on the coordinator is always acceptable to the signer burn fanout that follows.
fn validate_burn_reason(reason: &str) -> Result<(), FrostStoreError> {
    if reason.is_empty()
        || reason.len() > MAX_BURN_REASON_BYTES
        || reason.trim() != reason
        || reason.bytes().any(|byte| byte.is_ascii_control())
    {
        Err(FrostStoreError::Conflict(
            "coordinator burn reason is invalid",
        ))
    } else {
        Ok(())
    }
}

fn validate_availability_receipt(receipt: &str) -> Result<(), FrostStoreError> {
    if receipt.is_empty()
        || receipt.len() > MAX_AVAILABILITY_RECEIPT_BYTES
        || receipt.trim() != receipt
    {
        Err(FrostStoreError::Conflict("availability receipt is invalid"))
    } else {
        Ok(())
    }
}

fn coordinator_error(error: impl std::fmt::Display) -> FrostStoreError {
    FrostStoreError::InvalidState(error.to_string())
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

#[cfg(test)]
mod tests {
    use super::{validate_burn_reason, MAX_BURN_REASON_BYTES};

    #[test]
    fn burn_reasons_reject_control_characters() {
        for reason in [
            "operator\tabort",
            "operator\nabort",
            "operator\rabort",
            "operator\u{0}abort",
        ] {
            assert!(
                validate_burn_reason(reason).is_err(),
                "control character accepted in {reason:?}"
            );
        }
    }

    #[test]
    fn burn_reasons_accept_plain_text() {
        assert!(validate_burn_reason("operator abort").is_ok());
        assert!(validate_burn_reason(&"a".repeat(MAX_BURN_REASON_BYTES)).is_ok());
    }

    #[test]
    fn burn_reasons_reject_empty_padded_and_oversized() {
        assert!(validate_burn_reason("").is_err());
        assert!(validate_burn_reason(" operator abort").is_err());
        assert!(validate_burn_reason("operator abort ").is_err());
        assert!(validate_burn_reason(&"a".repeat(MAX_BURN_REASON_BYTES + 1)).is_err());
    }
}
