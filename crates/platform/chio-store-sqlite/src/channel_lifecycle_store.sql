CREATE TABLE IF NOT EXISTS channel_state_records (
    channel_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    state_kind TEXT NOT NULL CHECK (state_kind IN ('initial', 'signed')),
    state_digest TEXT NOT NULL CHECK (
        length(state_digest) = 64
        AND state_digest NOT GLOB '*[^0-9a-f]*'
    ),
    checkpoint_sequence INTEGER NOT NULL CHECK (checkpoint_sequence > 0),
    checkpoint_digest TEXT NOT NULL CHECK (
        length(checkpoint_digest) = 64
        AND checkpoint_digest NOT GLOB '*[^0-9a-f]*'
    ),
    state_json BLOB NOT NULL CHECK (length(state_json) BETWEEN 1 AND 1048576),
    operation_id TEXT,
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    recorded_at_unix_ms INTEGER NOT NULL CHECK (recorded_at_unix_ms > 0),
    PRIMARY KEY (channel_id, sequence),
    UNIQUE (channel_id, state_digest),
    UNIQUE (channel_id, sequence, state_digest),
    UNIQUE (
        channel_id, sequence, state_digest, checkpoint_sequence, checkpoint_digest
    ),
    FOREIGN KEY (operation_id) REFERENCES admission_operations(operation_id),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch),
    CHECK (
        length(channel_id) = 64
        AND channel_id NOT GLOB '*[^0-9a-f]*'
        AND (operation_id IS NULL
             OR (length(operation_id) = 64
                 AND operation_id NOT GLOB '*[^0-9a-f]*'))
        AND ((sequence = 0 AND state_kind = 'initial' AND operation_id IS NULL)
             OR (sequence > 0 AND state_kind = 'signed'))
    )
);

CREATE TRIGGER IF NOT EXISTS channel_state_records_exact_lease
BEFORE INSERT ON channel_state_records
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'channel state has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS channel_state_records_immutable
BEFORE UPDATE ON channel_state_records
BEGIN
    SELECT RAISE(ABORT, 'channel state is immutable');
END;

CREATE TRIGGER IF NOT EXISTS channel_state_records_no_delete
BEFORE DELETE ON channel_state_records
BEGIN
    SELECT RAISE(ABORT, 'channel state is immutable');
END;

CREATE TABLE IF NOT EXISTS channel_lifecycle_records (
    channel_id TEXT NOT NULL PRIMARY KEY CHECK (
        length(channel_id) = 64
        AND channel_id NOT GLOB '*[^0-9a-f]*'
    ),
    open_intent_digest TEXT NOT NULL CHECK (
        length(open_intent_digest) = 64
        AND open_intent_digest NOT GLOB '*[^0-9a-f]*'
    ),
    open_intent_json BLOB NOT NULL CHECK (length(open_intent_json) BETWEEN 1 AND 1048576),
    open_digest TEXT NOT NULL CHECK (
        length(open_digest) = 64
        AND open_digest NOT GLOB '*[^0-9a-f]*'
    ),
    open_json BLOB NOT NULL CHECK (length(open_json) BETWEEN 1 AND 1048576),
    lifecycle_json BLOB NOT NULL CHECK (length(lifecycle_json) BETWEEN 1 AND 1048576),
    escrow_json BLOB NOT NULL CHECK (length(escrow_json) BETWEEN 1 AND 1048576),
    lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN (
        'open', 'close_pending', 'closing', 'released', 'refunded', 'incident'
    )),
    latest_state_digest TEXT NOT NULL CHECK (
        length(latest_state_digest) = 64
        AND latest_state_digest NOT GLOB '*[^0-9a-f]*'
    ),
    latest_sequence INTEGER NOT NULL CHECK (latest_sequence >= 0),
    state_version INTEGER NOT NULL CHECK (state_version > 0),
    lifecycle_fence INTEGER NOT NULL CHECK (lifecycle_fence > 0),
    live_reservation_id TEXT,
    operation_id TEXT,
    channel_head_digest TEXT NOT NULL CHECK (
        length(channel_head_digest) = 64
        AND channel_head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    escrow_head_digest TEXT NOT NULL CHECK (
        length(escrow_head_digest) = 64
        AND escrow_head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    checkpoint_sequence INTEGER NOT NULL CHECK (checkpoint_sequence > 0),
    checkpoint_digest TEXT NOT NULL CHECK (
        length(checkpoint_digest) = 64
        AND checkpoint_digest NOT GLOB '*[^0-9a-f]*'
    ),
    record_version INTEGER NOT NULL CHECK (record_version > 0),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms > 0),
    UNIQUE (open_digest),
    FOREIGN KEY (
        channel_id, latest_sequence, latest_state_digest
    ) REFERENCES channel_state_records(
        channel_id, sequence, state_digest
    ),
    FOREIGN KEY (operation_id) REFERENCES admission_operations(operation_id),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch),
    CHECK (
        (live_reservation_id IS NULL AND operation_id IS NULL)
        OR
        (length(live_reservation_id) = 64
         AND live_reservation_id NOT GLOB '*[^0-9a-f]*'
         AND length(operation_id) = 64
         AND operation_id NOT GLOB '*[^0-9a-f]*')
    )
);

CREATE INDEX IF NOT EXISTS channel_lifecycle_records_live_reservation
    ON channel_lifecycle_records(live_reservation_id, operation_id);

CREATE TRIGGER IF NOT EXISTS channel_lifecycle_records_exact_lease_insert
BEFORE INSERT ON channel_lifecycle_records
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'channel lifecycle has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS channel_lifecycle_records_initial_checkpoint_insert
BEFORE INSERT ON channel_lifecycle_records
WHEN NOT EXISTS (
    SELECT 1 FROM channel_state_records
    WHERE channel_id = NEW.channel_id
      AND sequence = NEW.latest_sequence
      AND state_digest = NEW.latest_state_digest
      AND checkpoint_sequence = NEW.checkpoint_sequence
      AND checkpoint_digest = NEW.checkpoint_digest
)
BEGIN
    SELECT RAISE(ABORT, 'channel lifecycle initial checkpoint is not retained');
END;

CREATE TRIGGER IF NOT EXISTS channel_lifecycle_records_exact_lease_update
BEFORE UPDATE ON channel_lifecycle_records
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'channel lifecycle has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS channel_lifecycle_records_immutable_identity
BEFORE UPDATE OF channel_id, open_intent_digest, open_intent_json, open_digest, open_json
ON channel_lifecycle_records
BEGIN
    SELECT RAISE(ABORT, 'channel lifecycle identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS channel_lifecycle_records_versioned
BEFORE UPDATE ON channel_lifecycle_records
WHEN NEW.record_version <> OLD.record_version + 1
  OR NEW.state_version <> OLD.state_version + 1
  OR NEW.lifecycle_fence <> OLD.lifecycle_fence + 1
BEGIN
    SELECT RAISE(ABORT, 'channel lifecycle update requires one version and fence increment');
END;

CREATE TRIGGER IF NOT EXISTS channel_lifecycle_records_no_delete
BEFORE DELETE ON channel_lifecycle_records
BEGIN
    SELECT RAISE(ABORT, 'channel lifecycle is immutable');
END;

CREATE TABLE IF NOT EXISTS channel_prepared_admission_plans (
    operation_id TEXT NOT NULL PRIMARY KEY CHECK (
        length(operation_id) = 64
        AND operation_id NOT GLOB '*[^0-9a-f]*'
    ),
    request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 512),
    request_namespace_digest TEXT NOT NULL CHECK (
        length(request_namespace_digest) = 64
        AND request_namespace_digest NOT GLOB '*[^0-9a-f]*'
    ),
    request_binding_digest TEXT NOT NULL CHECK (
        length(request_binding_digest) = 64
        AND request_binding_digest NOT GLOB '*[^0-9a-f]*'
    ),
    provider_binding_digest TEXT NOT NULL CHECK (
        length(provider_binding_digest) = 64
        AND provider_binding_digest NOT GLOB '*[^0-9a-f]*'
    ),
    reservation_id TEXT NOT NULL UNIQUE CHECK (
        length(reservation_id) = 64
        AND reservation_id NOT GLOB '*[^0-9a-f]*'
    ),
    channel_id TEXT NOT NULL,
    open_digest TEXT NOT NULL,
    prior_state_digest TEXT NOT NULL,
    prior_sequence INTEGER NOT NULL CHECK (prior_sequence >= 0),
    reservation_proposal_digest TEXT NOT NULL CHECK (
        length(reservation_proposal_digest) = 64
        AND reservation_proposal_digest NOT GLOB '*[^0-9a-f]*'
    ),
    lifecycle_state TEXT NOT NULL CHECK (lifecycle_state = 'open'),
    state_version INTEGER NOT NULL CHECK (state_version > 0),
    lifecycle_fence INTEGER NOT NULL CHECK (lifecycle_fence > 0),
    live_reservation_id TEXT,
    lifecycle_operation_id TEXT,
    channel_head_digest TEXT NOT NULL CHECK (
        length(channel_head_digest) = 64
        AND channel_head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    escrow_head_digest TEXT NOT NULL CHECK (
        length(escrow_head_digest) = 64
        AND escrow_head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    checkpoint_sequence INTEGER NOT NULL CHECK (checkpoint_sequence > 0),
    checkpoint_digest TEXT NOT NULL CHECK (
        length(checkpoint_digest) = 64
        AND checkpoint_digest NOT GLOB '*[^0-9a-f]*'
    ),
    plan_digest TEXT NOT NULL UNIQUE CHECK (
        length(plan_digest) = 64
        AND plan_digest NOT GLOB '*[^0-9a-f]*'
    ),
    plan_json BLOB NOT NULL CHECK (length(plan_json) BETWEEN 1 AND 4194304),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms > 0),
    UNIQUE (
        operation_id, reservation_id, channel_id,
        request_binding_digest, provider_binding_digest, prior_sequence,
        plan_digest
    ),
    FOREIGN KEY (operation_id) REFERENCES admission_operations(operation_id),
    FOREIGN KEY (channel_id) REFERENCES channel_lifecycle_records(channel_id),
    FOREIGN KEY (
        channel_id, prior_sequence, prior_state_digest,
        checkpoint_sequence, checkpoint_digest
    ) REFERENCES channel_state_records(
        channel_id, sequence, state_digest, checkpoint_sequence, checkpoint_digest
    ),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch),
    CHECK (live_reservation_id IS NULL AND lifecycle_operation_id IS NULL)
);

CREATE INDEX IF NOT EXISTS channel_prepared_admission_plans_channel
    ON channel_prepared_admission_plans(channel_id, prior_sequence, created_at_unix_ms);

CREATE TRIGGER IF NOT EXISTS channel_prepared_admission_plans_exact_lease
BEFORE INSERT ON channel_prepared_admission_plans
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'channel prepared plan has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS channel_prepared_admission_plans_immutable
BEFORE UPDATE ON channel_prepared_admission_plans
BEGIN
    SELECT RAISE(ABORT, 'channel prepared plan is immutable');
END;

CREATE TRIGGER IF NOT EXISTS channel_prepared_admission_plans_no_delete
BEFORE DELETE ON channel_prepared_admission_plans
BEGIN
    SELECT RAISE(ABORT, 'channel prepared plan is immutable');
END;

CREATE TABLE IF NOT EXISTS channel_reservation_records (
    reservation_id TEXT NOT NULL PRIMARY KEY CHECK (
        length(reservation_id) = 64
        AND reservation_id NOT GLOB '*[^0-9a-f]*'
    ),
    operation_id TEXT NOT NULL UNIQUE,
    channel_id TEXT NOT NULL,
    prior_sequence INTEGER NOT NULL CHECK (prior_sequence >= 0),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    prepared_plan_digest TEXT NOT NULL CHECK (
        length(prepared_plan_digest) = 64
        AND prepared_plan_digest NOT GLOB '*[^0-9a-f]*'
    ),
    reservation_digest TEXT NOT NULL UNIQUE CHECK (
        length(reservation_digest) = 64
        AND reservation_digest NOT GLOB '*[^0-9a-f]*'
    ),
    reservation_json BLOB NOT NULL CHECK (length(reservation_json) BETWEEN 1 AND 1048576),
    authority_pins_digest TEXT NOT NULL CHECK (
        length(authority_pins_digest) = 64
        AND authority_pins_digest NOT GLOB '*[^0-9a-f]*'
    ),
    authority_pins_json BLOB NOT NULL CHECK (
        length(authority_pins_json) BETWEEN 1 AND 262144
    ),
    request_binding_digest TEXT NOT NULL CHECK (
        length(request_binding_digest) = 64
        AND request_binding_digest NOT GLOB '*[^0-9a-f]*'
    ),
    provider_binding_digest TEXT NOT NULL CHECK (
        length(provider_binding_digest) = 64
        AND provider_binding_digest NOT GLOB '*[^0-9a-f]*'
    ),
    stage_batch_id TEXT NOT NULL CHECK (
        length(stage_batch_id) = 64
        AND stage_batch_id NOT GLOB '*[^0-9a-f]*'
    ),
    stage_descriptor_kind TEXT NOT NULL CHECK (
        stage_descriptor_kind = 'chio.channel.transition-replay.v1'
    ),
    stage_descriptor_key TEXT NOT NULL CHECK (
        stage_descriptor_key = 'reservation:' || operation_id
    ),
    stage_descriptor_digest TEXT NOT NULL CHECK (
        length(stage_descriptor_digest) = 64
        AND stage_descriptor_digest NOT GLOB '*[^0-9a-f]*'
    ),
    base_checkpoint_sequence INTEGER NOT NULL CHECK (base_checkpoint_sequence > 0),
    base_checkpoint_digest TEXT NOT NULL CHECK (
        length(base_checkpoint_digest) = 64
        AND base_checkpoint_digest NOT GLOB '*[^0-9a-f]*'
    ),
    ready_checkpoint_digest TEXT NOT NULL CHECK (
        length(ready_checkpoint_digest) = 64
        AND ready_checkpoint_digest NOT GLOB '*[^0-9a-f]*'
    ),
    ready_checkpoint_sequence INTEGER NOT NULL CHECK (ready_checkpoint_sequence > 0),
    ready_effect_head_digest TEXT NOT NULL CHECK (
        length(ready_effect_head_digest) = 64
        AND ready_effect_head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    replay_protocol_digest TEXT NOT NULL CHECK (
        length(replay_protocol_digest) = 64
        AND replay_protocol_digest NOT GLOB '*[^0-9a-f]*'
    ),
    replay_content_digest TEXT NOT NULL CHECK (
        length(replay_content_digest) = 64
        AND replay_content_digest NOT GLOB '*[^0-9a-f]*'
    ),
    replay_json BLOB NOT NULL CHECK (
        length(replay_json) BETWEEN 1 AND 4194304
    ),
    disposition TEXT NOT NULL CHECK (
        disposition IN ('pending_anchor', 'live', 'consumed', 'cancelled', 'incident')
    ),
    record_version INTEGER NOT NULL CHECK (record_version > 0),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms > 0),
    FOREIGN KEY (
        operation_id, reservation_id, channel_id,
        request_binding_digest, provider_binding_digest, prior_sequence,
        prepared_plan_digest
    ) REFERENCES channel_prepared_admission_plans(
        operation_id, reservation_id, channel_id,
        request_binding_digest, provider_binding_digest, prior_sequence,
        plan_digest
    ),
    FOREIGN KEY (
        stage_batch_id, ready_checkpoint_sequence, ready_checkpoint_digest,
        stage_descriptor_kind, stage_descriptor_key, stage_descriptor_digest
    ) REFERENCES economic_state_stages(
        batch_id, checkpoint_sequence, checkpoint_digest,
        descriptor_kind, descriptor_key, descriptor_digest
    ),
    FOREIGN KEY (channel_id) REFERENCES channel_lifecycle_records(channel_id),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch),
    CHECK (sequence = prior_sequence + 1),
    CHECK (replay_content_digest = stage_descriptor_digest),
    CHECK (base_checkpoint_sequence < ready_checkpoint_sequence)
);

CREATE UNIQUE INDEX IF NOT EXISTS channel_reservation_records_channel_active
    ON channel_reservation_records(channel_id)
    WHERE disposition IN ('pending_anchor', 'live');

CREATE TRIGGER IF NOT EXISTS channel_lifecycle_records_reservation_binding
BEFORE UPDATE ON channel_lifecycle_records
WHEN NEW.live_reservation_id IS NOT NULL
 AND NOT EXISTS (
     SELECT 1 FROM channel_reservation_records AS reservation
     WHERE reservation.reservation_id = NEW.live_reservation_id
       AND reservation.operation_id = NEW.operation_id
       AND reservation.channel_id = NEW.channel_id
       AND reservation.disposition IN ('pending_anchor', 'live')
       AND reservation.ready_checkpoint_sequence = NEW.checkpoint_sequence
       AND reservation.ready_checkpoint_digest = NEW.checkpoint_digest
 )
BEGIN
    SELECT RAISE(ABORT, 'channel lifecycle has no exact active reservation');
END;

CREATE TRIGGER IF NOT EXISTS channel_reservation_records_pending_lifecycle_insert
BEFORE INSERT ON channel_reservation_records
WHEN NEW.disposition = 'pending_anchor'
 AND NOT EXISTS (
     SELECT 1
     FROM channel_lifecycle_records AS lifecycle
     JOIN channel_prepared_admission_plans AS prepared
       ON prepared.operation_id = NEW.operation_id
     WHERE lifecycle.channel_id = NEW.channel_id
       AND lifecycle.lifecycle_state = prepared.lifecycle_state
       AND lifecycle.latest_sequence = prepared.prior_sequence
       AND lifecycle.latest_state_digest = prepared.prior_state_digest
       AND lifecycle.state_version = prepared.state_version
       AND lifecycle.lifecycle_fence = prepared.lifecycle_fence
       AND lifecycle.live_reservation_id IS NULL
       AND lifecycle.operation_id IS NULL
       AND lifecycle.channel_head_digest = prepared.channel_head_digest
       AND lifecycle.escrow_head_digest = prepared.escrow_head_digest
       AND lifecycle.checkpoint_sequence = prepared.checkpoint_sequence
       AND lifecycle.checkpoint_digest = prepared.checkpoint_digest
 )
BEGIN
    SELECT RAISE(ABORT, 'pending channel reservation base lifecycle mismatch');
END;

CREATE TRIGGER IF NOT EXISTS channel_reservation_records_live_lifecycle_update
BEFORE UPDATE OF disposition ON channel_reservation_records
WHEN NEW.disposition = 'live'
 AND NOT EXISTS (
     SELECT 1 FROM channel_lifecycle_records
     WHERE channel_id = NEW.channel_id
       AND lifecycle_state = 'open'
       AND live_reservation_id = NEW.reservation_id
       AND operation_id = NEW.operation_id
       AND checkpoint_sequence = NEW.ready_checkpoint_sequence
       AND checkpoint_digest = NEW.ready_checkpoint_digest
 )
BEGIN
    SELECT RAISE(ABORT, 'live channel reservation lifecycle mismatch');
END;

CREATE TRIGGER IF NOT EXISTS channel_reservation_records_exact_lease_insert
BEFORE INSERT ON channel_reservation_records
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'channel reservation has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS channel_reservation_records_exact_lease_update
BEFORE UPDATE ON channel_reservation_records
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'channel reservation has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS channel_reservation_records_immutable_evidence
BEFORE UPDATE OF reservation_id, operation_id, channel_id, prior_sequence, sequence,
                 prepared_plan_digest,
                 reservation_digest, reservation_json,
                 authority_pins_digest, authority_pins_json,
                 request_binding_digest, provider_binding_digest,
                 stage_batch_id, stage_descriptor_kind, stage_descriptor_key,
                 stage_descriptor_digest,
                 base_checkpoint_sequence, base_checkpoint_digest,
                 ready_checkpoint_sequence, ready_checkpoint_digest,
                 ready_effect_head_digest,
                 replay_protocol_digest, replay_content_digest, replay_json
ON channel_reservation_records
BEGIN
    SELECT RAISE(ABORT, 'channel reservation evidence is immutable');
END;

CREATE TRIGGER IF NOT EXISTS channel_reservation_records_monotonic_disposition
BEFORE UPDATE OF disposition ON channel_reservation_records
WHEN NEW.disposition <> OLD.disposition
 AND NOT (
     (OLD.disposition = 'pending_anchor' AND NEW.disposition IN ('live', 'cancelled', 'incident'))
     OR (OLD.disposition = 'live' AND NEW.disposition IN ('consumed', 'cancelled', 'incident'))
 )
BEGIN
    SELECT RAISE(ABORT, 'channel reservation disposition is terminal');
END;

CREATE TRIGGER IF NOT EXISTS channel_reservation_records_versioned
BEFORE UPDATE ON channel_reservation_records
WHEN NEW.record_version <> OLD.record_version + 1
BEGIN
    SELECT RAISE(ABORT, 'channel reservation update requires one version increment');
END;

CREATE TRIGGER IF NOT EXISTS channel_reservation_records_no_delete
BEFORE DELETE ON channel_reservation_records
BEGIN
    SELECT RAISE(ABORT, 'channel reservation is immutable');
END;
