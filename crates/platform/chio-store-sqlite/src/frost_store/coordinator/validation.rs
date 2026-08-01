use std::collections::BTreeSet;

use chio_core::canonical::canonical_json_bytes;
use chio_core::sha256_hex;
use chio_federation::frost::{
    frost_authorization_session_id, frost_authorization_slot_id, FrostAuthorizationBodyV1,
    FrostAuthorizationV1, FrostRosterV1,
};
use chio_federation_authority::{
    aggregate_frost_authorization, build_frost_signing_package, frost_participant_identifier_bytes,
    validate_frost_signing_commitment, verify_frost_signature_share,
};
use rusqlite::{Connection, OptionalExtension};

use super::{
    coordinator_projection_key, coordinator_record_digest, invalid, stored_bound_checkpoint,
    StoredCoordinator, ValidatedRequest, MAX_LEASE_TTL_MS, MAX_RUNTIME_IDENTIFIER_BYTES,
};
use crate::frost_store::{
    FrostCoordinatorLease, FrostCoordinatorSessionRequest, FrostCoordinatorSessionState,
    FrostStoreError,
};

pub(super) fn verify_coordinator_invariants(
    connection: &Connection,
) -> Result<(), FrostStoreError> {
    let mut statement = connection
        .prepare("SELECT session_id FROM frost_coordinator_sessions ORDER BY session_id")
        .map_err(crate::frost_store::sqlite_error)?;
    let session_ids = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(crate::frost_store::sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(crate::frost_store::sqlite_error)?;
    drop(statement);
    for session_id in session_ids {
        let stored = super::persistence::load_coordinator_query(connection, &session_id)?
            .ok_or_else(|| invalid("coordinator session disappeared during verification"))?;
        verify_stored_coordinator(&stored)?;
        let latest = connection
            .query_row(
                r#"
                SELECT projection_sequence, record_digest
                FROM frost_projection_commits
                WHERE projection_key = ?1
                ORDER BY projection_sequence DESC LIMIT 1
                "#,
                [coordinator_projection_key(&session_id)],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(crate::frost_store::sqlite_error)?
            .ok_or_else(|| invalid("coordinator session lacks a projection commit"))?;
        if read_u64(latest.0, "coordinator projection sequence")? != stored.row_version
            || latest.1 != stored.record_digest
        {
            return Err(invalid(
                "coordinator session diverges from its projection head",
            ));
        }
    }
    Ok(())
}

fn verify_stored_coordinator(stored: &StoredCoordinator) -> Result<(), FrostStoreError> {
    let body: FrostAuthorizationBodyV1 = serde_json::from_slice(&stored.authorization_body_json)
        .map_err(|error| invalid(error.to_string()))?;
    let roster: FrostRosterV1 =
        serde_json::from_slice(&stored.roster_json).map_err(|error| invalid(error.to_string()))?;
    body.validate()
        .map_err(|error| invalid(error.to_string()))?;
    roster
        .validate_for_active_resolution()
        .map_err(|error| invalid(error.to_string()))?;
    let bound = stored_bound_checkpoint(stored)?;
    if canonical_json_bytes(&body).map_err(|error| invalid(error.to_string()))?
        != stored.authorization_body_json
        || canonical_json_bytes(&roster).map_err(|error| invalid(error.to_string()))?
            != stored.roster_json
        || canonical_json_bytes(&bound).map_err(|error| invalid(error.to_string()))?
            != stored.bound_checkpoint_json
        || body.scope_id != stored.scope_id
        || body.key_epoch != stored.key_epoch
        || body.authorization_id != stored.authorization_id
        || body.roster_digest != stored.roster_digest
        || body.resource_fence != stored.resource_fence
        || frost_authorization_session_id(&body).map_err(|error| invalid(error.to_string()))?
            != stored.session_id
        || frost_authorization_slot_id(&body).map_err(|error| invalid(error.to_string()))?
            != stored.authorization_slot_id
        || sha256_hex(
            &body
                .signing_bytes()
                .map_err(|error| invalid(error.to_string()))?,
        ) != stored.signing_message_digest
        || roster.roster_digest != stored.roster_digest
        || stored.bound_checkpoint_digest != bound.checkpoint_digest
    {
        return Err(invalid("coordinator record binding is invalid"));
    }
    if let Some(package) = stored.signing_package.as_deref() {
        if stored.signing_package_digest.as_deref() != Some(sha256_hex(package).as_str()) {
            return Err(invalid("coordinator signing package digest is invalid"));
        }
    }
    for (participant_id, commitment) in &stored.commitments {
        let signer_identifier = frost_participant_identifier_bytes(participant_id)
            .map_err(|error| invalid(error.to_string()))?;
        validate_frost_signing_commitment(&roster, participant_id, &signer_identifier, commitment)
            .map_err(|error| invalid(error.to_string()))?;
    }
    if let Some(package) = stored.signing_package.as_deref() {
        let expected = build_frost_signing_package(&body, &roster, &stored.commitments)
            .map_err(|error| invalid(error.to_string()))?;
        if stored.signing_participants.as_deref() != Some(expected.participant_ids())
            || package != expected.bytes()
        {
            return Err(invalid("coordinator signing package is not reproducible"));
        }
        for (participant_id, share) in &stored.shares {
            verify_frost_signature_share(&body, &roster, package, participant_id, share)
                .map_err(|error| invalid(error.to_string()))?;
        }
    }
    if let Some(blob) = stored.authorization_blob.as_deref() {
        let proof: FrostAuthorizationV1 =
            serde_json::from_slice(blob).map_err(|error| invalid(error.to_string()))?;
        if proof.body != body
            || proof
                .canonical_bytes()
                .map_err(|error| invalid(error.to_string()))?
                != blob
            || stored.authorization_blob_digest.as_deref() != Some(sha256_hex(blob).as_str())
        {
            return Err(invalid("coordinator authorization bytes are invalid"));
        }
        let package = stored
            .signing_package
            .as_deref()
            .ok_or_else(|| invalid("coordinator authorization lacks a signing package"))?;
        let expected = aggregate_frost_authorization(&body, &roster, package, &stored.shares)
            .map_err(|error| invalid(error.to_string()))?;
        if expected != proof {
            return Err(invalid(
                "coordinator authorization does not match its persisted shares",
            ));
        }
    }
    let selected = stored
        .signing_participants
        .as_ref()
        .map(|participants| participants.iter().collect::<BTreeSet<_>>());
    if stored
        .signing_participants
        .as_ref()
        .is_some_and(|participants| {
            selected.as_ref().map_or(0, BTreeSet::len) != participants.len()
        })
        || stored.shares.keys().any(|participant| {
            selected
                .as_ref()
                .is_none_or(|set| !set.contains(participant))
        })
        || coordinator_record_digest(stored)? != stored.record_digest
    {
        return Err(invalid("coordinator record content is invalid"));
    }
    Ok(())
}

pub(super) fn validate_request(
    request: &FrostCoordinatorSessionRequest<'_>,
) -> Result<ValidatedRequest, FrostStoreError> {
    request
        .body
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    validate_runtime_identifier(request.coordinator_id, "coordinator id")?;
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
        roster_json: canonical_json_bytes(request.active_roster.roster())
            .map_err(|error| invalid(error.to_string()))?,
        signing_message_digest: sha256_hex(&signing_bytes),
    })
}

pub(super) fn verify_active_request(
    request: &FrostCoordinatorSessionRequest<'_>,
) -> Result<(), FrostStoreError> {
    let roster = request.active_roster.roster();
    if request.body.scope_id != request.active_roster.scope_id()
        || request.body.key_epoch != request.active_roster.key_epoch()
        || request.body.roster_digest != request.active_roster.roster_digest()
        || request.body.quorum_n != roster.threshold
        || request.body.quorum_m != roster.participant_count
        || request.body.quorum_scope != roster.authority_scope
        || !roster.allowed_domains.contains(&request.body.domain)
    {
        return Err(FrostStoreError::Conflict(
            "coordinator request does not use the active roster",
        ));
    }
    Ok(())
}

pub(super) fn matches_request(
    stored: &StoredCoordinator,
    request: &FrostCoordinatorSessionRequest<'_>,
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
        && stored.authorization_body_json == validated.authorization_body_json
        && stored.roster_json == validated.roster_json
}

pub(super) fn verify_lease(
    stored: &StoredCoordinator,
    lease: &FrostCoordinatorLease,
    trusted_now_unix_ms: u64,
) -> Result<(), FrostStoreError> {
    if stored.session_id != lease.session_id
        || stored.authorization_slot_id != lease.authorization_slot_id
        || stored.coordinator_id != lease.coordinator_id
        || stored.coordinator_worker_id != lease.worker_id
        || stored.coordinator_lease_id != lease.lease_id
        || stored.coordinator_owner_epoch != lease.owner_epoch
        || stored.lease_expires_at_unix_ms != lease.expires_at_unix_ms
        || trusted_now_unix_ms >= stored.lease_expires_at_unix_ms
    {
        return Err(FrostStoreError::Fenced);
    }
    Ok(())
}

pub(super) fn ensure_live_state(stored: &StoredCoordinator) -> Result<(), FrostStoreError> {
    if matches!(
        stored.state,
        FrostCoordinatorSessionState::Completed | FrostCoordinatorSessionState::Burned
    ) {
        Err(FrostStoreError::Conflict(
            "terminal coordinator session cannot be mutated",
        ))
    } else {
        Ok(())
    }
}

pub(super) fn validate_lease(
    worker_id: &str,
    lease_id: &str,
    lease_ttl_ms: u64,
) -> Result<(), FrostStoreError> {
    validate_runtime_identifier(worker_id, "worker id")?;
    validate_runtime_identifier(lease_id, "lease id")?;
    if lease_ttl_ms == 0 || lease_ttl_ms > MAX_LEASE_TTL_MS {
        return Err(FrostStoreError::Conflict(
            "coordinator lease TTL is outside the supported range",
        ));
    }
    Ok(())
}

fn validate_runtime_identifier(value: &str, field: &'static str) -> Result<(), FrostStoreError> {
    if value.is_empty()
        || value.len() > MAX_RUNTIME_IDENTIFIER_BYTES
        || value.trim() != value
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(FrostStoreError::InvalidState(format!(
            "{field} must be unpadded printable ASCII"
        )));
    }
    Ok(())
}

fn read_u64(value: i64, field: &'static str) -> Result<u64, FrostStoreError> {
    u64::try_from(value).map_err(|_| invalid(format!("{field} is negative")))
}
