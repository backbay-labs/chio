CREATE TABLE IF NOT EXISTS chio_channel_release_publisher_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    trusted_time_high_water_unix_ms INTEGER NOT NULL CHECK (
        trusted_time_high_water_unix_ms >= 0
    )
);

INSERT OR IGNORE INTO chio_channel_release_publisher_meta (
    singleton, trusted_time_high_water_unix_ms
) VALUES (1, 0);

CREATE TRIGGER IF NOT EXISTS chio_channel_release_publisher_meta_no_delete
BEFORE DELETE ON chio_channel_release_publisher_meta
BEGIN
    SELECT RAISE(ABORT, 'channel release publisher clock is immutable');
END;

CREATE TRIGGER IF NOT EXISTS chio_channel_release_publisher_meta_monotonic
BEFORE UPDATE ON chio_channel_release_publisher_meta
WHEN NEW.singleton <> OLD.singleton
  OR NEW.trusted_time_high_water_unix_ms < OLD.trusted_time_high_water_unix_ms
BEGIN
    SELECT RAISE(ABORT, 'channel release publisher clock regressed');
END;

CREATE TABLE IF NOT EXISTS chio_channel_release_publications (
    channel_id TEXT PRIMARY KEY CHECK (
        length(channel_id) = 64
        AND channel_id NOT GLOB '*[^0-9a-f]*'
    ),
    chain_id TEXT NOT NULL CHECK (chain_id <> ''),
    escrow_contract TEXT NOT NULL CHECK (escrow_contract <> ''),
    escrow_id TEXT NOT NULL UNIQUE CHECK (escrow_id <> ''),
    open_digest TEXT NOT NULL CHECK (
        length(open_digest) = 64
        AND open_digest NOT GLOB '*[^0-9a-f]*'
    ),
    close_digest TEXT NOT NULL CHECK (
        length(close_digest) = 64
        AND close_digest NOT GLOB '*[^0-9a-f]*'
    ),
    close_body_digest TEXT NOT NULL CHECK (
        length(close_body_digest) = 64
        AND close_body_digest NOT GLOB '*[^0-9a-f]*'
    ),
    effective_close_digest TEXT NOT NULL CHECK (
        length(effective_close_digest) = 64
        AND effective_close_digest NOT GLOB '*[^0-9a-f]*'
    ),
    final_state_digest TEXT NOT NULL CHECK (
        length(final_state_digest) = 64
        AND final_state_digest NOT GLOB '*[^0-9a-f]*'
    ),
    final_state_sequence INTEGER NOT NULL CHECK (final_state_sequence >= 0),
    source_channel_state_version INTEGER NOT NULL CHECK (source_channel_state_version > 0),
    source_escrow_reservation_version INTEGER NOT NULL CHECK (
        source_escrow_reservation_version > 0
    ),
    source_lifecycle_fence INTEGER NOT NULL CHECK (source_lifecycle_fence > 0),
    source_checkpoint_sequence INTEGER NOT NULL CHECK (source_checkpoint_sequence > 0),
    source_checkpoint_digest TEXT NOT NULL CHECK (
        length(source_checkpoint_digest) = 64
        AND source_checkpoint_digest NOT GLOB '*[^0-9a-f]*'
    ),
    source_channel_head_digest TEXT NOT NULL CHECK (
        length(source_channel_head_digest) = 64
        AND source_channel_head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    source_escrow_head_digest TEXT NOT NULL CHECK (
        length(source_escrow_head_digest) = 64
        AND source_escrow_head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    closing_checkpoint_sequence INTEGER NOT NULL CHECK (closing_checkpoint_sequence > 0),
    closing_checkpoint_digest TEXT NOT NULL CHECK (
        length(closing_checkpoint_digest) = 64
        AND closing_checkpoint_digest NOT GLOB '*[^0-9a-f]*'
    ),
    closing_channel_head_digest TEXT NOT NULL CHECK (
        length(closing_channel_head_digest) = 64
        AND closing_channel_head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    closing_escrow_head_digest TEXT NOT NULL CHECK (
        length(closing_escrow_head_digest) = 64
        AND closing_escrow_head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    closing_lifecycle_json BLOB NOT NULL CHECK (
        length(closing_lifecycle_json) BETWEEN 1 AND 1048576
    ),
    closing_escrow_json BLOB NOT NULL CHECK (
        length(closing_escrow_json) BETWEEN 1 AND 1048576
    ),
    bound_token_base_units TEXT NOT NULL CHECK (bound_token_base_units <> ''),
    release_token_base_units TEXT NOT NULL CHECK (release_token_base_units <> ''),
    refund_token_base_units TEXT NOT NULL CHECK (refund_token_base_units <> ''),
    original_operator TEXT NOT NULL CHECK (original_operator <> ''),
    original_operator_key_hash TEXT NOT NULL CHECK (original_operator_key_hash <> ''),
    beneficiary_address TEXT NOT NULL CHECK (beneficiary_address <> ''),
    asset_binding_digest TEXT NOT NULL CHECK (
        length(asset_binding_digest) = 64
        AND asset_binding_digest NOT GLOB '*[^0-9a-f]*'
    ),
    original_dispatch_digest TEXT NOT NULL CHECK (
        length(original_dispatch_digest) = 64
        AND original_dispatch_digest NOT GLOB '*[^0-9a-f]*'
    ),
    close_submission_cutoff_unix_ms INTEGER NOT NULL CHECK (
        close_submission_cutoff_unix_ms > 0
    ),
    escrow_deadline_unix_ms INTEGER NOT NULL CHECK (escrow_deadline_unix_ms > 0),
    publisher_fence INTEGER NOT NULL CHECK (publisher_fence > 0),
    authorized_at_unix_ms INTEGER NOT NULL CHECK (authorized_at_unix_ms > 0),
    frost_slot_id TEXT NOT NULL UNIQUE CHECK (
        length(frost_slot_id) = 64
        AND frost_slot_id NOT GLOB '*[^0-9a-f]*'
    ),
    frost_authorization_id TEXT NOT NULL CHECK (
        length(frost_authorization_id) = 64
        AND frost_authorization_id NOT GLOB '*[^0-9a-f]*'
    ),
    frost_action_digest TEXT NOT NULL CHECK (
        length(frost_action_digest) = 64
        AND frost_action_digest NOT GLOB '*[^0-9a-f]*'
    ),
    frost_envelope_digest TEXT NOT NULL CHECK (
        length(frost_envelope_digest) = 64
        AND frost_envelope_digest NOT GLOB '*[^0-9a-f]*'
    ),
    frost_scope_id TEXT NOT NULL CHECK (frost_scope_id <> ''),
    frost_resource_id TEXT NOT NULL CHECK (frost_resource_id <> ''),
    frost_resource_version INTEGER NOT NULL CHECK (frost_resource_version > 0),
    frost_resource_fence INTEGER NOT NULL CHECK (frost_resource_fence > 0),
    frost_roster_digest TEXT NOT NULL CHECK (
        length(frost_roster_digest) = 64
        AND frost_roster_digest NOT GLOB '*[^0-9a-f]*'
    ),
    frost_key_epoch INTEGER NOT NULL CHECK (frost_key_epoch > 0),
    frost_issued_at_unix_ms INTEGER NOT NULL CHECK (frost_issued_at_unix_ms > 0),
    authorization_digest TEXT NOT NULL UNIQUE CHECK (
        length(authorization_digest) = 64
        AND authorization_digest NOT GLOB '*[^0-9a-f]*'
    ),
    authorization_json BLOB NOT NULL CHECK (
        length(authorization_json) BETWEEN 1 AND 1048576
    ),
    publication_binding_digest TEXT NOT NULL UNIQUE CHECK (
        length(publication_binding_digest) = 64
        AND publication_binding_digest NOT GLOB '*[^0-9a-f]*'
    ),
    prepared_call_digest TEXT NOT NULL UNIQUE CHECK (
        length(prepared_call_digest) = 64
        AND prepared_call_digest NOT GLOB '*[^0-9a-f]*'
    ),
    prepared_call_json BLOB NOT NULL CHECK (
        length(prepared_call_json) BETWEEN 1 AND 1048576
    ),
    status TEXT NOT NULL CHECK (status IN (
        'dispatch_committed', 'submitted', 'unknown', 'incident'
    )),
    transaction_hash TEXT,
    failure_detail TEXT CHECK (
        failure_detail IS NULL
        OR length(CAST(failure_detail AS BLOB)) BETWEEN 1 AND 4096
    ),
    record_version INTEGER NOT NULL CHECK (record_version > 0),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms > 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms > 0),
    FOREIGN KEY (channel_id) REFERENCES channel_lifecycle_records(channel_id),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch),
    CHECK (
        (status = 'dispatch_committed'
         AND transaction_hash IS NULL AND failure_detail IS NULL)
        OR (status = 'submitted'
            AND transaction_hash IS NOT NULL AND transaction_hash <> ''
            AND failure_detail IS NULL)
        OR (status IN ('unknown', 'incident')
            AND transaction_hash IS NULL
            AND failure_detail IS NOT NULL AND failure_detail <> '')
    )
);

CREATE TRIGGER IF NOT EXISTS chio_channel_release_publications_exact_lease_insert
BEFORE INSERT ON chio_channel_release_publications
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'channel release publication has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS chio_channel_release_publications_exact_lease_update
BEFORE UPDATE ON chio_channel_release_publications
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'channel release publication has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS chio_channel_release_publications_immutable_binding
BEFORE UPDATE OF
    channel_id, chain_id, escrow_contract, escrow_id,
    open_digest, close_digest, close_body_digest, effective_close_digest,
    final_state_digest, final_state_sequence,
    source_channel_state_version, source_escrow_reservation_version,
    source_lifecycle_fence, source_checkpoint_sequence, source_checkpoint_digest,
    source_channel_head_digest, source_escrow_head_digest,
    closing_checkpoint_sequence, closing_checkpoint_digest,
    closing_channel_head_digest, closing_escrow_head_digest,
    closing_lifecycle_json, closing_escrow_json,
    bound_token_base_units, release_token_base_units, refund_token_base_units,
    original_operator, original_operator_key_hash, beneficiary_address,
    asset_binding_digest, original_dispatch_digest,
    close_submission_cutoff_unix_ms, escrow_deadline_unix_ms,
    publisher_fence, authorized_at_unix_ms,
    frost_slot_id, frost_authorization_id, frost_action_digest,
    frost_envelope_digest, frost_scope_id, frost_resource_id,
    frost_resource_version, frost_resource_fence, frost_roster_digest,
    frost_key_epoch, frost_issued_at_unix_ms,
    authorization_digest, authorization_json, publication_binding_digest,
    prepared_call_digest, prepared_call_json, created_at_unix_ms
ON chio_channel_release_publications
BEGIN
    SELECT RAISE(ABORT, 'channel release publication binding is immutable');
END;

CREATE TRIGGER IF NOT EXISTS chio_channel_release_publications_versioned
BEFORE UPDATE ON chio_channel_release_publications
WHEN NEW.record_version <> OLD.record_version + 1
BEGIN
    SELECT RAISE(ABORT, 'channel release publication update requires one version increment');
END;

CREATE TRIGGER IF NOT EXISTS chio_channel_release_publications_terminal_state
BEFORE UPDATE OF status ON chio_channel_release_publications
WHEN OLD.status <> 'dispatch_committed'
  OR NEW.status NOT IN ('submitted', 'unknown', 'incident')
BEGIN
    SELECT RAISE(ABORT, 'channel release publication is already terminal');
END;

CREATE TRIGGER IF NOT EXISTS chio_channel_release_publications_no_delete
BEFORE DELETE ON chio_channel_release_publications
BEGIN
    SELECT RAISE(ABORT, 'channel release publication is immutable');
END;
