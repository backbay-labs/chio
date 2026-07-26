pub(super) const FROST_STORE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS frost_ceremonies (
    ceremony_id TEXT PRIMARY KEY CHECK (
        length(ceremony_id) = 64
        AND ceremony_id NOT GLOB '*[^0-9a-f]*'
    ),
    config_json BLOB NOT NULL CHECK (length(config_json) > 0),
    config_digest TEXT NOT NULL CHECK (
        length(config_digest) = 64
        AND config_digest NOT GLOB '*[^0-9a-f]*'
    ),
    participant_set_digest TEXT NOT NULL CHECK (
        length(participant_set_digest) = 64
        AND participant_set_digest NOT GLOB '*[^0-9a-f]*'
    ),
    scope_id TEXT NOT NULL CHECK (scope_id <> ''),
    key_epoch INTEGER NOT NULL CHECK (key_epoch > 0),
    local_participant_id TEXT NOT NULL CHECK (local_participant_id <> ''),
    state TEXT NOT NULL CHECK (
        state IN ('round1_ready', 'round2_ready', 'completed')
    ),
    state_version INTEGER NOT NULL CHECK (state_version > 0),
    custody_generation TEXT NOT NULL CHECK (custody_generation <> ''),
    secret_kind TEXT NOT NULL CHECK (
        secret_kind IN ('round1', 'round2', 'key_package')
    ),
    secret_nonce BLOB NOT NULL CHECK (length(secret_nonce) = 12),
    secret_ciphertext BLOB NOT NULL CHECK (length(secret_ciphertext) > 16),
    output_nonce BLOB CHECK (output_nonce IS NULL OR length(output_nonce) = 12),
    output_ciphertext BLOB,
    input_transcript_digest TEXT CHECK (
        input_transcript_digest IS NULL
        OR (
            length(input_transcript_digest) = 64
            AND input_transcript_digest NOT GLOB '*[^0-9a-f]*'
        )
    ),
    public_key_package BLOB,
    group_public_key TEXT CHECK (
        group_public_key IS NULL
        OR (
            length(group_public_key) = 64
            AND group_public_key NOT GLOB '*[^0-9a-f]*'
        )
    ),
    verification_shares_json BLOB,
    source_store_uuid TEXT NOT NULL CHECK (source_store_uuid <> ''),
    source_lease_id TEXT NOT NULL CHECK (source_lease_id <> ''),
    source_owner_epoch INTEGER NOT NULL CHECK (source_owner_epoch > 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms > 0),
    completed_at_unix_ms INTEGER CHECK (completed_at_unix_ms > 0),
    record_digest TEXT NOT NULL CHECK (
        length(record_digest) = 64
        AND record_digest NOT GLOB '*[^0-9a-f]*'
    ),
    CHECK (
        (state = 'round1_ready' AND state_version = 1
         AND secret_kind = 'round1'
         AND output_nonce IS NOT NULL AND output_ciphertext IS NOT NULL
         AND input_transcript_digest IS NULL
         AND public_key_package IS NULL AND group_public_key IS NULL
         AND verification_shares_json IS NULL AND completed_at_unix_ms IS NULL)
        OR
        (state = 'round2_ready' AND state_version = 2
         AND secret_kind = 'round2'
         AND output_nonce IS NOT NULL AND output_ciphertext IS NOT NULL
         AND input_transcript_digest IS NOT NULL
         AND public_key_package IS NULL AND group_public_key IS NULL
         AND verification_shares_json IS NULL AND completed_at_unix_ms IS NULL)
        OR
        (state = 'completed' AND state_version = 3
         AND secret_kind = 'key_package'
         AND output_nonce IS NULL AND output_ciphertext IS NULL
         AND input_transcript_digest IS NOT NULL
         AND public_key_package IS NOT NULL AND group_public_key IS NOT NULL
         AND verification_shares_json IS NOT NULL
         AND completed_at_unix_ms IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS frost_ceremonies_scope_epoch
ON frost_ceremonies(scope_id, key_epoch, state);

CREATE UNIQUE INDEX IF NOT EXISTS frost_ceremonies_scope_epoch_participant
ON frost_ceremonies(scope_id, key_epoch, local_participant_id);

CREATE TABLE IF NOT EXISTS frost_roster_history (
    scope_id TEXT NOT NULL CHECK (scope_id <> ''),
    key_epoch INTEGER NOT NULL CHECK (key_epoch > 0),
    roster_id TEXT NOT NULL CHECK (
        length(roster_id) = 64 AND roster_id NOT GLOB '*[^0-9a-f]*'
    ),
    roster_digest TEXT NOT NULL CHECK (
        length(roster_digest) = 64 AND roster_digest NOT GLOB '*[^0-9a-f]*'
    ),
    roster_json BLOB NOT NULL CHECK (length(roster_json) > 0),
    checkpoint_sequence INTEGER NOT NULL CHECK (checkpoint_sequence > 0),
    checkpoint_digest TEXT NOT NULL CHECK (
        length(checkpoint_digest) = 64 AND checkpoint_digest NOT GLOB '*[^0-9a-f]*'
    ),
    checkpoint_json BLOB NOT NULL CHECK (length(checkpoint_json) > 0),
    activation_fence INTEGER NOT NULL CHECK (activation_fence > 0),
    clock_high_water INTEGER NOT NULL CHECK (clock_high_water > 0),
    activated_at_unix_ms INTEGER NOT NULL CHECK (activated_at_unix_ms > 0),
    source_store_uuid TEXT NOT NULL CHECK (source_store_uuid <> ''),
    source_lease_id TEXT NOT NULL CHECK (source_lease_id <> ''),
    source_owner_epoch INTEGER NOT NULL CHECK (source_owner_epoch > 0),
    record_digest TEXT NOT NULL CHECK (
        length(record_digest) = 64 AND record_digest NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (scope_id, key_epoch),
    UNIQUE (roster_id),
    UNIQUE (roster_digest),
    UNIQUE (checkpoint_digest)
);

CREATE TABLE IF NOT EXISTS frost_active_rosters (
    scope_id TEXT PRIMARY KEY CHECK (scope_id <> ''),
    key_epoch INTEGER NOT NULL CHECK (key_epoch > 0),
    roster_digest TEXT NOT NULL CHECK (
        length(roster_digest) = 64 AND roster_digest NOT GLOB '*[^0-9a-f]*'
    ),
    checkpoint_sequence INTEGER NOT NULL CHECK (checkpoint_sequence > 0),
    checkpoint_digest TEXT NOT NULL CHECK (
        length(checkpoint_digest) = 64 AND checkpoint_digest NOT GLOB '*[^0-9a-f]*'
    ),
    activation_fence INTEGER NOT NULL CHECK (activation_fence > 0),
    clock_high_water INTEGER NOT NULL CHECK (clock_high_water > 0),
    source_store_uuid TEXT NOT NULL CHECK (source_store_uuid <> ''),
    source_lease_id TEXT NOT NULL CHECK (source_lease_id <> ''),
    source_owner_epoch INTEGER NOT NULL CHECK (source_owner_epoch > 0),
    FOREIGN KEY (scope_id, key_epoch)
        REFERENCES frost_roster_history(scope_id, key_epoch),
    FOREIGN KEY (roster_digest)
        REFERENCES frost_roster_history(roster_digest),
    FOREIGN KEY (checkpoint_digest)
        REFERENCES frost_roster_history(checkpoint_digest)
);

CREATE TABLE IF NOT EXISTS frost_roster_rotations (
    rotation_id TEXT PRIMARY KEY CHECK (
        length(rotation_id) = 64 AND rotation_id NOT GLOB '*[^0-9a-f]*'
    ),
    scope_id TEXT NOT NULL CHECK (scope_id <> ''),
    state TEXT NOT NULL CHECK (
        state IN ('staged', 'anchor_advanced', 'active', 'discarded')
    ),
    state_version INTEGER NOT NULL CHECK (state_version BETWEEN 1 AND 3),
    predecessor_checkpoint_digest TEXT NOT NULL CHECK (
        length(predecessor_checkpoint_digest) = 64
        AND predecessor_checkpoint_digest NOT GLOB '*[^0-9a-f]*'
    ),
    predecessor_checkpoint_json BLOB NOT NULL CHECK (
        length(predecessor_checkpoint_json) > 0
    ),
    target_roster_digest TEXT NOT NULL CHECK (
        length(target_roster_digest) = 64
        AND target_roster_digest NOT GLOB '*[^0-9a-f]*'
    ),
    target_roster_json BLOB NOT NULL CHECK (length(target_roster_json) > 0),
    target_key_epoch INTEGER NOT NULL CHECK (target_key_epoch > 1),
    rotation_authorization_digest TEXT NOT NULL CHECK (
        length(rotation_authorization_digest) = 64
        AND rotation_authorization_digest NOT GLOB '*[^0-9a-f]*'
    ),
    burn_summary_json BLOB NOT NULL CHECK (length(burn_summary_json) > 0),
    old_session_burn_root TEXT NOT NULL CHECK (
        length(old_session_burn_root) = 64
        AND old_session_burn_root NOT GLOB '*[^0-9a-f]*'
    ),
    expected_checkpoint_sequence INTEGER NOT NULL CHECK (
        expected_checkpoint_sequence > 1
    ),
    activation_fence INTEGER NOT NULL CHECK (activation_fence > 0),
    clock_high_water INTEGER NOT NULL CHECK (clock_high_water > 0),
    anchored_checkpoint_digest TEXT CHECK (
        anchored_checkpoint_digest IS NULL
        OR (
            length(anchored_checkpoint_digest) = 64
            AND anchored_checkpoint_digest NOT GLOB '*[^0-9a-f]*'
        )
    ),
    anchored_checkpoint_json BLOB,
    source_store_uuid TEXT NOT NULL CHECK (source_store_uuid <> ''),
    source_lease_id TEXT NOT NULL CHECK (source_lease_id <> ''),
    source_owner_epoch INTEGER NOT NULL CHECK (source_owner_epoch > 0),
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms > 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK (
        updated_at_unix_ms >= created_at_unix_ms
    ),
    record_digest TEXT NOT NULL CHECK (
        length(record_digest) = 64 AND record_digest NOT GLOB '*[^0-9a-f]*'
    ),
    CHECK (
        (state = 'staged' AND state_version = 1
         AND anchored_checkpoint_digest IS NULL AND anchored_checkpoint_json IS NULL)
        OR
        (state IN ('anchor_advanced', 'discarded') AND state_version = 2
         AND (
             (state = 'anchor_advanced' AND anchored_checkpoint_digest IS NOT NULL
              AND anchored_checkpoint_json IS NOT NULL)
             OR
             (state = 'discarded' AND anchored_checkpoint_digest IS NULL
              AND anchored_checkpoint_json IS NULL)
         ))
        OR
        (state = 'active' AND state_version = 3
         AND anchored_checkpoint_digest IS NOT NULL
         AND anchored_checkpoint_json IS NOT NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS frost_roster_rotations_target
ON frost_roster_rotations(scope_id, target_key_epoch);

CREATE UNIQUE INDEX IF NOT EXISTS frost_roster_rotations_live_scope
ON frost_roster_rotations(scope_id)
WHERE state IN ('staged', 'anchor_advanced');

CREATE TABLE IF NOT EXISTS frost_signer_sessions (
    session_id TEXT NOT NULL CHECK (
        length(session_id) = 64 AND session_id NOT GLOB '*[^0-9a-f]*'
    ),
    participant_id TEXT NOT NULL CHECK (participant_id <> ''),
    authorization_slot_id TEXT NOT NULL CHECK (
        length(authorization_slot_id) = 64
        AND authorization_slot_id NOT GLOB '*[^0-9a-f]*'
    ),
    scope_id TEXT NOT NULL CHECK (scope_id <> ''),
    key_epoch INTEGER NOT NULL CHECK (key_epoch > 0),
    authorization_id TEXT NOT NULL CHECK (
        length(authorization_id) = 64
        AND authorization_id NOT GLOB '*[^0-9a-f]*'
    ),
    signing_message_digest TEXT NOT NULL CHECK (
        length(signing_message_digest) = 64
        AND signing_message_digest NOT GLOB '*[^0-9a-f]*'
    ),
    roster_digest TEXT NOT NULL CHECK (
        length(roster_digest) = 64 AND roster_digest NOT GLOB '*[^0-9a-f]*'
    ),
    coordinator_id TEXT NOT NULL CHECK (coordinator_id <> ''),
    resource_fence INTEGER NOT NULL CHECK (resource_fence > 0),
    ceremony_id TEXT NOT NULL CHECK (
        length(ceremony_id) = 64 AND ceremony_id NOT GLOB '*[^0-9a-f]*'
    ),
    authorization_body_json BLOB NOT NULL CHECK (length(authorization_body_json) > 0),
    bound_checkpoint_digest TEXT NOT NULL CHECK (
        length(bound_checkpoint_digest) = 64
        AND bound_checkpoint_digest NOT GLOB '*[^0-9a-f]*'
    ),
    bound_checkpoint_json BLOB NOT NULL CHECK (length(bound_checkpoint_json) > 0),
    signer_identifier BLOB NOT NULL CHECK (length(signer_identifier) > 0),
    verification_share TEXT NOT NULL CHECK (
        length(verification_share) = 64
        AND verification_share NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT NOT NULL CHECK (
        state IN ('prepared', 'commitment_published', 'share_ready', 'completed', 'burned')
    ),
    state_version INTEGER NOT NULL CHECK (state_version BETWEEN 1 AND 4),
    custody_generation TEXT NOT NULL CHECK (custody_generation <> ''),
    nonce_aad BLOB NOT NULL CHECK (length(nonce_aad) > 0),
    nonce_ciphertext BLOB,
    nonce_nonce BLOB CHECK (nonce_nonce IS NULL OR length(nonce_nonce) = 12),
    commitment_bytes BLOB NOT NULL CHECK (length(commitment_bytes) > 0),
    commitment_digest TEXT NOT NULL CHECK (
        length(commitment_digest) = 64
        AND commitment_digest NOT GLOB '*[^0-9a-f]*'
    ),
    signing_package_digest TEXT CHECK (
        signing_package_digest IS NULL
        OR (length(signing_package_digest) = 64
            AND signing_package_digest NOT GLOB '*[^0-9a-f]*')
    ),
    signature_share BLOB,
    burn_reason TEXT,
    source_store_uuid TEXT NOT NULL CHECK (source_store_uuid <> ''),
    source_lease_id TEXT NOT NULL CHECK (source_lease_id <> ''),
    source_owner_epoch INTEGER NOT NULL CHECK (source_owner_epoch > 0),
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms > 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= created_at_unix_ms),
    record_digest TEXT NOT NULL CHECK (
        length(record_digest) = 64 AND record_digest NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (session_id, participant_id),
    UNIQUE (authorization_slot_id, participant_id),
    CHECK (
        (state = 'prepared' AND state_version = 1
         AND nonce_ciphertext IS NOT NULL AND nonce_nonce IS NOT NULL
         AND signing_package_digest IS NULL AND signature_share IS NULL
         AND burn_reason IS NULL)
        OR
        (state = 'commitment_published' AND state_version = 2
         AND nonce_ciphertext IS NOT NULL AND nonce_nonce IS NOT NULL
         AND signing_package_digest IS NULL AND signature_share IS NULL
         AND burn_reason IS NULL)
        OR
        (state = 'share_ready' AND state_version = 3
         AND nonce_ciphertext IS NOT NULL AND nonce_nonce IS NOT NULL
         AND signing_package_digest IS NOT NULL AND signature_share IS NOT NULL
         AND burn_reason IS NULL)
        OR
        (state = 'completed' AND state_version = 4
         AND nonce_ciphertext IS NULL AND nonce_nonce IS NULL
         AND signing_package_digest IS NOT NULL AND signature_share IS NOT NULL
         AND burn_reason IS NULL)
        OR
        (state = 'burned' AND state_version BETWEEN 2 AND 4
         AND nonce_ciphertext IS NULL AND nonce_nonce IS NULL
         AND signature_share IS NULL AND burn_reason IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS frost_coordinator_sessions (
    session_id TEXT PRIMARY KEY CHECK (
        length(session_id) = 64 AND session_id NOT GLOB '*[^0-9a-f]*'
    ),
    authorization_slot_id TEXT NOT NULL UNIQUE CHECK (
        length(authorization_slot_id) = 64
        AND authorization_slot_id NOT GLOB '*[^0-9a-f]*'
    ),
    scope_id TEXT NOT NULL CHECK (scope_id <> ''),
    key_epoch INTEGER NOT NULL CHECK (key_epoch > 0),
    authorization_id TEXT NOT NULL CHECK (
        length(authorization_id) = 64
        AND authorization_id NOT GLOB '*[^0-9a-f]*'
    ),
    signing_message_digest TEXT NOT NULL CHECK (
        length(signing_message_digest) = 64
        AND signing_message_digest NOT GLOB '*[^0-9a-f]*'
    ),
    roster_digest TEXT NOT NULL CHECK (
        length(roster_digest) = 64 AND roster_digest NOT GLOB '*[^0-9a-f]*'
    ),
    coordinator_id TEXT NOT NULL CHECK (coordinator_id <> ''),
    resource_fence INTEGER NOT NULL CHECK (resource_fence > 0),
    authorization_body_json BLOB NOT NULL CHECK (length(authorization_body_json) > 0),
    roster_json BLOB NOT NULL CHECK (length(roster_json) > 0),
    bound_checkpoint_digest TEXT NOT NULL CHECK (
        length(bound_checkpoint_digest) = 64
        AND bound_checkpoint_digest NOT GLOB '*[^0-9a-f]*'
    ),
    bound_checkpoint_json BLOB NOT NULL CHECK (length(bound_checkpoint_json) > 0),
    state TEXT NOT NULL CHECK (
        state IN (
            'collecting_commitments', 'package_ready', 'authorization_ready',
            'completed', 'burned'
        )
    ),
    row_version INTEGER NOT NULL CHECK (row_version > 0),
    commitments_json BLOB NOT NULL CHECK (length(commitments_json) > 0),
    signing_participants_json BLOB,
    signing_package BLOB,
    signing_package_digest TEXT CHECK (
        signing_package_digest IS NULL
        OR (length(signing_package_digest) = 64
            AND signing_package_digest NOT GLOB '*[^0-9a-f]*')
    ),
    shares_json BLOB NOT NULL CHECK (length(shares_json) > 0),
    authorization_blob BLOB,
    authorization_blob_digest TEXT CHECK (
        authorization_blob_digest IS NULL
        OR (length(authorization_blob_digest) = 64
            AND authorization_blob_digest NOT GLOB '*[^0-9a-f]*')
    ),
    availability_receipt TEXT,
    burn_reason TEXT,
    coordinator_worker_id TEXT NOT NULL CHECK (coordinator_worker_id <> ''),
    coordinator_lease_id TEXT NOT NULL CHECK (coordinator_lease_id <> ''),
    coordinator_owner_epoch INTEGER NOT NULL CHECK (coordinator_owner_epoch > 0),
    lease_expires_at_unix_ms INTEGER NOT NULL CHECK (lease_expires_at_unix_ms > 0),
    source_store_uuid TEXT NOT NULL CHECK (source_store_uuid <> ''),
    source_lease_id TEXT NOT NULL CHECK (source_lease_id <> ''),
    source_owner_epoch INTEGER NOT NULL CHECK (source_owner_epoch > 0),
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms > 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= created_at_unix_ms),
    record_digest TEXT NOT NULL CHECK (
        length(record_digest) = 64 AND record_digest NOT GLOB '*[^0-9a-f]*'
    ),
    CHECK (
        (state = 'collecting_commitments'
         AND signing_participants_json IS NULL
         AND signing_package IS NULL AND signing_package_digest IS NULL
         AND authorization_blob IS NULL AND authorization_blob_digest IS NULL
         AND availability_receipt IS NULL AND burn_reason IS NULL)
        OR
        (state = 'package_ready'
         AND signing_participants_json IS NOT NULL
         AND signing_package IS NOT NULL AND signing_package_digest IS NOT NULL
         AND authorization_blob IS NULL AND authorization_blob_digest IS NULL
         AND availability_receipt IS NULL AND burn_reason IS NULL)
        OR
        (state IN ('authorization_ready', 'completed')
         AND signing_participants_json IS NOT NULL
         AND signing_package IS NOT NULL AND signing_package_digest IS NOT NULL
         AND authorization_blob IS NOT NULL AND authorization_blob_digest IS NOT NULL
         AND availability_receipt IS NOT NULL AND burn_reason IS NULL)
        OR
        (state = 'burned' AND burn_reason IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS frost_projection_commits (
    projection_key TEXT NOT NULL CHECK (projection_key <> ''),
    projection_sequence INTEGER NOT NULL CHECK (projection_sequence > 0),
    projection_type TEXT NOT NULL CHECK (
        projection_type IN ('ceremony', 'rotation', 'signer', 'coordinator')
    ),
    mutation_kind TEXT NOT NULL CHECK (mutation_kind <> ''),
    record_digest TEXT NOT NULL CHECK (
        length(record_digest) = 64
        AND record_digest NOT GLOB '*[^0-9a-f]*'
    ),
    previous_chain_digest TEXT NOT NULL CHECK (
        length(previous_chain_digest) = 64
        AND previous_chain_digest NOT GLOB '*[^0-9a-f]*'
    ),
    chain_digest TEXT NOT NULL CHECK (
        length(chain_digest) = 64
        AND chain_digest NOT GLOB '*[^0-9a-f]*'
    ),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    PRIMARY KEY (projection_key, projection_sequence)
);

CREATE UNIQUE INDEX IF NOT EXISTS frost_projection_commits_chain
ON frost_projection_commits(chain_digest);

CREATE TRIGGER IF NOT EXISTS frost_ceremonies_no_delete
BEFORE DELETE ON frost_ceremonies
BEGIN
    SELECT RAISE(ABORT, 'FROST ceremony records cannot be deleted');
END;

CREATE TRIGGER IF NOT EXISTS frost_roster_history_immutable
BEFORE UPDATE ON frost_roster_history
BEGIN
    SELECT RAISE(ABORT, 'FROST roster history is immutable');
END;

CREATE TRIGGER IF NOT EXISTS frost_roster_history_no_delete
BEFORE DELETE ON frost_roster_history
BEGIN
    SELECT RAISE(ABORT, 'FROST roster history is immutable');
END;

CREATE TRIGGER IF NOT EXISTS frost_active_rosters_no_delete
BEFORE DELETE ON frost_active_rosters
BEGIN
    SELECT RAISE(ABORT, 'FROST active roster cannot be deleted');
END;

CREATE TRIGGER IF NOT EXISTS frost_active_rosters_monotonic
BEFORE UPDATE ON frost_active_rosters
WHEN NEW.key_epoch <> OLD.key_epoch + 1
  OR NEW.checkpoint_sequence <> OLD.checkpoint_sequence + 1
  OR NEW.activation_fence <= OLD.activation_fence
  OR NEW.clock_high_water < OLD.clock_high_water
BEGIN
    SELECT RAISE(ABORT, 'FROST active roster update is not monotonic');
END;

CREATE TRIGGER IF NOT EXISTS frost_roster_rotations_no_delete
BEFORE DELETE ON frost_roster_rotations
BEGIN
    SELECT RAISE(ABORT, 'FROST rotation records cannot be deleted');
END;

CREATE TRIGGER IF NOT EXISTS frost_roster_rotations_transition
BEFORE UPDATE ON frost_roster_rotations
WHEN NEW.rotation_id <> OLD.rotation_id
  OR NEW.scope_id <> OLD.scope_id
  OR NEW.predecessor_checkpoint_digest <> OLD.predecessor_checkpoint_digest
  OR NEW.predecessor_checkpoint_json <> OLD.predecessor_checkpoint_json
  OR NEW.target_roster_digest <> OLD.target_roster_digest
  OR NEW.target_roster_json <> OLD.target_roster_json
  OR NEW.target_key_epoch <> OLD.target_key_epoch
  OR NEW.rotation_authorization_digest <> OLD.rotation_authorization_digest
  OR NEW.burn_summary_json <> OLD.burn_summary_json
  OR NEW.old_session_burn_root <> OLD.old_session_burn_root
  OR NEW.expected_checkpoint_sequence <> OLD.expected_checkpoint_sequence
  OR NEW.activation_fence <> OLD.activation_fence
  OR NEW.clock_high_water <> OLD.clock_high_water
  OR NEW.source_store_uuid <> OLD.source_store_uuid
  OR NEW.source_owner_epoch < OLD.source_owner_epoch
  OR NEW.created_at_unix_ms <> OLD.created_at_unix_ms
  OR NEW.updated_at_unix_ms < OLD.updated_at_unix_ms
  OR NOT (
      (OLD.state = 'staged' AND NEW.state IN ('anchor_advanced', 'discarded')
       AND NEW.state_version = 2)
      OR
      (OLD.state = 'anchor_advanced' AND NEW.state = 'active'
       AND NEW.state_version = 3
       AND NEW.anchored_checkpoint_digest = OLD.anchored_checkpoint_digest
       AND NEW.anchored_checkpoint_json = OLD.anchored_checkpoint_json)
  )
BEGIN
    SELECT RAISE(ABORT, 'invalid FROST rotation transition');
END;

CREATE TRIGGER IF NOT EXISTS frost_signer_sessions_no_delete
BEFORE DELETE ON frost_signer_sessions
BEGIN
    SELECT RAISE(ABORT, 'FROST signer tombstones cannot be deleted');
END;

CREATE TRIGGER IF NOT EXISTS frost_signer_sessions_transition
BEFORE UPDATE ON frost_signer_sessions
WHEN NEW.session_id <> OLD.session_id
  OR NEW.participant_id <> OLD.participant_id
  OR NEW.authorization_slot_id <> OLD.authorization_slot_id
  OR NEW.scope_id <> OLD.scope_id
  OR NEW.key_epoch <> OLD.key_epoch
  OR NEW.authorization_id <> OLD.authorization_id
  OR NEW.signing_message_digest <> OLD.signing_message_digest
  OR NEW.roster_digest <> OLD.roster_digest
  OR NEW.coordinator_id <> OLD.coordinator_id
  OR NEW.resource_fence <> OLD.resource_fence
  OR NEW.ceremony_id <> OLD.ceremony_id
  OR NEW.authorization_body_json <> OLD.authorization_body_json
  OR NEW.bound_checkpoint_digest <> OLD.bound_checkpoint_digest
  OR NEW.bound_checkpoint_json <> OLD.bound_checkpoint_json
  OR NEW.signer_identifier <> OLD.signer_identifier
  OR NEW.verification_share <> OLD.verification_share
  OR NEW.custody_generation <> OLD.custody_generation
  OR NEW.nonce_aad <> OLD.nonce_aad
  OR NEW.commitment_bytes <> OLD.commitment_bytes
  OR NEW.commitment_digest <> OLD.commitment_digest
  OR NEW.source_store_uuid <> OLD.source_store_uuid
  OR NEW.source_owner_epoch < OLD.source_owner_epoch
  OR NEW.created_at_unix_ms <> OLD.created_at_unix_ms
  OR NEW.updated_at_unix_ms < OLD.updated_at_unix_ms
  OR NOT (
      (OLD.state = 'prepared'
       AND (
           (NEW.state = 'commitment_published' AND NEW.state_version = 2
            AND NEW.nonce_ciphertext = OLD.nonce_ciphertext
            AND NEW.nonce_nonce = OLD.nonce_nonce
            AND NEW.signing_package_digest IS NULL
            AND NEW.signature_share IS NULL
            AND NEW.burn_reason IS NULL)
           OR
           (NEW.state = 'burned' AND NEW.state_version = 2
            AND NEW.nonce_ciphertext IS NULL
            AND NEW.nonce_nonce IS NULL
            AND NEW.signing_package_digest IS NULL
            AND NEW.signature_share IS NULL
            AND NEW.burn_reason IS NOT NULL)
       ))
      OR
      (OLD.state = 'commitment_published'
       AND (
           (NEW.state = 'share_ready' AND NEW.state_version = 3
            AND NEW.nonce_ciphertext = OLD.nonce_ciphertext
            AND NEW.nonce_nonce = OLD.nonce_nonce
            AND NEW.signing_package_digest IS NOT NULL
            AND NEW.signature_share IS NOT NULL
            AND NEW.burn_reason IS NULL)
           OR
           (NEW.state = 'burned' AND NEW.state_version = 3
            AND NEW.nonce_ciphertext IS NULL
            AND NEW.nonce_nonce IS NULL
            AND NEW.signing_package_digest IS NULL
            AND NEW.signature_share IS NULL
            AND NEW.burn_reason IS NOT NULL)
       ))
      OR
      (OLD.state = 'share_ready'
       AND (
           (NEW.state = 'completed' AND NEW.state_version = 4
            AND NEW.nonce_ciphertext IS NULL
            AND NEW.nonce_nonce IS NULL
            AND NEW.signing_package_digest = OLD.signing_package_digest
            AND NEW.signature_share = OLD.signature_share
            AND NEW.burn_reason IS NULL)
           OR
           (NEW.state = 'burned' AND NEW.state_version = 4
            AND NEW.nonce_ciphertext IS NULL
            AND NEW.nonce_nonce IS NULL
            AND NEW.signing_package_digest = OLD.signing_package_digest
            AND NEW.signature_share IS NULL
            AND NEW.burn_reason IS NOT NULL)
       ))
  )
BEGIN
    SELECT RAISE(ABORT, 'invalid FROST signer transition');
END;

CREATE TRIGGER IF NOT EXISTS frost_coordinator_sessions_no_delete
BEFORE DELETE ON frost_coordinator_sessions
BEGIN
    SELECT RAISE(ABORT, 'FROST coordinator tombstones cannot be deleted');
END;

CREATE TRIGGER IF NOT EXISTS frost_coordinator_sessions_transition
BEFORE UPDATE ON frost_coordinator_sessions
WHEN NEW.session_id <> OLD.session_id
  OR NEW.authorization_slot_id <> OLD.authorization_slot_id
  OR NEW.scope_id <> OLD.scope_id
  OR NEW.key_epoch <> OLD.key_epoch
  OR NEW.authorization_id <> OLD.authorization_id
  OR NEW.signing_message_digest <> OLD.signing_message_digest
  OR NEW.roster_digest <> OLD.roster_digest
  OR NEW.coordinator_id <> OLD.coordinator_id
  OR NEW.resource_fence <> OLD.resource_fence
  OR NEW.authorization_body_json <> OLD.authorization_body_json
  OR NEW.roster_json <> OLD.roster_json
  OR NEW.bound_checkpoint_digest <> OLD.bound_checkpoint_digest
  OR NEW.bound_checkpoint_json <> OLD.bound_checkpoint_json
  OR NEW.row_version <> OLD.row_version + 1
  OR NEW.source_store_uuid <> OLD.source_store_uuid
  OR NEW.source_owner_epoch < OLD.source_owner_epoch
  OR NEW.created_at_unix_ms <> OLD.created_at_unix_ms
  OR NEW.updated_at_unix_ms < OLD.updated_at_unix_ms
  OR NOT (
      (NEW.coordinator_worker_id = OLD.coordinator_worker_id
       AND NEW.coordinator_lease_id = OLD.coordinator_lease_id
       AND NEW.coordinator_owner_epoch = OLD.coordinator_owner_epoch
       AND NEW.lease_expires_at_unix_ms = OLD.lease_expires_at_unix_ms)
      OR
      (NEW.coordinator_worker_id = OLD.coordinator_worker_id
       AND NEW.coordinator_lease_id = OLD.coordinator_lease_id
       AND NEW.coordinator_owner_epoch = OLD.coordinator_owner_epoch
       AND NEW.lease_expires_at_unix_ms > OLD.lease_expires_at_unix_ms)
      OR
      ((NEW.coordinator_worker_id <> OLD.coordinator_worker_id
        OR NEW.coordinator_lease_id <> OLD.coordinator_lease_id)
       AND NEW.coordinator_owner_epoch = OLD.coordinator_owner_epoch + 1
       AND NEW.lease_expires_at_unix_ms > OLD.lease_expires_at_unix_ms)
  )
  OR NOT (
      (OLD.state = 'collecting_commitments'
       AND NEW.state = 'collecting_commitments'
       AND NEW.signing_participants_json IS NULL
       AND NEW.signing_package IS NULL AND NEW.signing_package_digest IS NULL
       AND NEW.shares_json = OLD.shares_json
       AND NEW.authorization_blob IS NULL AND NEW.authorization_blob_digest IS NULL
       AND NEW.availability_receipt IS NULL AND NEW.burn_reason IS NULL)
      OR
      (OLD.state = 'collecting_commitments'
       AND NEW.state = 'package_ready'
       AND NEW.commitments_json = OLD.commitments_json
       AND NEW.signing_participants_json IS NOT NULL
       AND NEW.signing_package IS NOT NULL AND NEW.signing_package_digest IS NOT NULL
       AND NEW.shares_json = OLD.shares_json
       AND NEW.authorization_blob IS NULL AND NEW.authorization_blob_digest IS NULL
       AND NEW.availability_receipt IS NULL AND NEW.burn_reason IS NULL)
      OR
      (OLD.state = 'package_ready'
       AND NEW.state = 'package_ready'
       AND NEW.commitments_json = OLD.commitments_json
       AND NEW.signing_participants_json = OLD.signing_participants_json
       AND NEW.signing_package = OLD.signing_package
       AND NEW.signing_package_digest = OLD.signing_package_digest
       AND NEW.authorization_blob IS NULL AND NEW.authorization_blob_digest IS NULL
       AND NEW.availability_receipt IS NULL AND NEW.burn_reason IS NULL)
      OR
      (OLD.state = 'package_ready'
       AND NEW.state = 'authorization_ready'
       AND NEW.commitments_json = OLD.commitments_json
       AND NEW.signing_participants_json = OLD.signing_participants_json
       AND NEW.signing_package = OLD.signing_package
       AND NEW.signing_package_digest = OLD.signing_package_digest
       AND NEW.shares_json = OLD.shares_json
       AND NEW.authorization_blob IS NOT NULL AND NEW.authorization_blob_digest IS NOT NULL
       AND NEW.availability_receipt IS NOT NULL AND NEW.burn_reason IS NULL)
      OR
      (OLD.state = 'authorization_ready'
       AND NEW.state = 'authorization_ready'
       AND NEW.commitments_json = OLD.commitments_json
       AND NEW.signing_participants_json = OLD.signing_participants_json
       AND NEW.signing_package = OLD.signing_package
       AND NEW.signing_package_digest = OLD.signing_package_digest
       AND NEW.shares_json = OLD.shares_json
       AND NEW.authorization_blob = OLD.authorization_blob
       AND NEW.authorization_blob_digest = OLD.authorization_blob_digest
       AND NEW.availability_receipt = OLD.availability_receipt
       AND NEW.burn_reason IS NULL)
      OR
      (OLD.state = 'authorization_ready'
       AND NEW.state = 'completed'
       AND NEW.commitments_json = OLD.commitments_json
       AND NEW.signing_participants_json = OLD.signing_participants_json
       AND NEW.signing_package = OLD.signing_package
       AND NEW.signing_package_digest = OLD.signing_package_digest
       AND NEW.shares_json = OLD.shares_json
       AND NEW.authorization_blob = OLD.authorization_blob
       AND NEW.authorization_blob_digest = OLD.authorization_blob_digest
       AND NEW.availability_receipt = OLD.availability_receipt
       AND NEW.burn_reason IS NULL)
      OR
      (OLD.state = 'completed'
       AND NEW.state = 'completed'
       AND NEW.commitments_json = OLD.commitments_json
       AND NEW.signing_participants_json = OLD.signing_participants_json
       AND NEW.signing_package = OLD.signing_package
       AND NEW.signing_package_digest = OLD.signing_package_digest
       AND NEW.shares_json = OLD.shares_json
       AND NEW.authorization_blob = OLD.authorization_blob
       AND NEW.authorization_blob_digest = OLD.authorization_blob_digest
       AND NEW.availability_receipt = OLD.availability_receipt
       AND NEW.burn_reason IS NULL)
      OR
      (OLD.state = 'package_ready'
       AND NEW.state = 'completed'
       AND NEW.commitments_json = OLD.commitments_json
       AND NEW.signing_participants_json = OLD.signing_participants_json
       AND NEW.signing_package = OLD.signing_package
       AND NEW.signing_package_digest = OLD.signing_package_digest
       AND NEW.shares_json = OLD.shares_json
       AND NEW.authorization_blob IS NOT NULL AND NEW.authorization_blob_digest IS NOT NULL
       AND NEW.availability_receipt IS NOT NULL AND NEW.burn_reason IS NULL)
      OR
      (OLD.state IN ('collecting_commitments', 'package_ready', 'authorization_ready')
       AND NEW.state = 'burned'
       AND NEW.commitments_json = OLD.commitments_json
       AND NEW.signing_participants_json IS OLD.signing_participants_json
       AND NEW.signing_package IS OLD.signing_package
       AND NEW.signing_package_digest IS OLD.signing_package_digest
       AND NEW.shares_json = OLD.shares_json
       AND NEW.authorization_blob IS OLD.authorization_blob
       AND NEW.authorization_blob_digest IS OLD.authorization_blob_digest
       AND NEW.availability_receipt IS OLD.availability_receipt
       AND NEW.burn_reason IS NOT NULL)
      OR
      (OLD.state = 'burned'
       AND NEW.state = 'burned'
       AND NEW.commitments_json = OLD.commitments_json
       AND NEW.signing_participants_json IS OLD.signing_participants_json
       AND NEW.signing_package IS OLD.signing_package
       AND NEW.signing_package_digest IS OLD.signing_package_digest
       AND NEW.shares_json = OLD.shares_json
       AND NEW.authorization_blob IS OLD.authorization_blob
       AND NEW.authorization_blob_digest IS OLD.authorization_blob_digest
       AND NEW.availability_receipt IS OLD.availability_receipt
       AND NEW.burn_reason = OLD.burn_reason)
  )
BEGIN
    SELECT RAISE(ABORT, 'invalid FROST coordinator transition');
END;

CREATE TRIGGER IF NOT EXISTS frost_projection_commits_immutable
BEFORE UPDATE ON frost_projection_commits
BEGIN
    SELECT RAISE(ABORT, 'FROST projection commits are immutable');
END;

CREATE TRIGGER IF NOT EXISTS frost_projection_commits_no_delete
BEFORE DELETE ON frost_projection_commits
BEGIN
    SELECT RAISE(ABORT, 'FROST projection commits are immutable');
END;
"#;
