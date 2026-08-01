CREATE TABLE IF NOT EXISTS tool_outcome_blobs (
    digest TEXT NOT NULL PRIMARY KEY CHECK (
        length(digest) = 64
        AND digest NOT GLOB '*[^0-9a-f]*'
    ),
    blob_size_bytes INTEGER NOT NULL CHECK (
        blob_size_bytes BETWEEN 1 AND 269484032
    ),
    -- Nullable so a terminal operation's raw payload can be compacted away while
    -- the digest and size stay behind for verification. Inserts still require it.
    canonical_bytes BLOB CHECK (
        canonical_bytes IS NULL
        OR length(canonical_bytes) = blob_size_bytes
    ),
    recorded_at_unix_ms INTEGER NOT NULL CHECK (recorded_at_unix_ms > 0),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch)
);

CREATE TRIGGER IF NOT EXISTS tool_outcome_blobs_exact_lease
BEFORE INSERT ON tool_outcome_blobs
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'tool outcome blob has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS tool_outcome_blobs_require_payload
BEFORE INSERT ON tool_outcome_blobs
WHEN NEW.canonical_bytes IS NULL
BEGIN
    SELECT RAISE(ABORT, 'tool outcome blob requires a payload');
END;

-- The only permitted updates flip payload retention state: compaction clears an
-- already recorded payload, and rehydration restores digest- and size-verified
-- canonical bytes supplied by a later owner. Identity, size and provenance stay
-- immutable, and a retained payload can never be rewritten in place.
CREATE TRIGGER IF NOT EXISTS tool_outcome_blobs_immutable
BEFORE UPDATE ON tool_outcome_blobs
WHEN NEW.digest <> OLD.digest
  OR NEW.blob_size_bytes <> OLD.blob_size_bytes
  OR NEW.recorded_at_unix_ms <> OLD.recorded_at_unix_ms
  OR NEW.store_uuid <> OLD.store_uuid
  OR NEW.store_lease_id <> OLD.store_lease_id
  OR NEW.store_owner_epoch <> OLD.store_owner_epoch
  OR (OLD.canonical_bytes IS NULL AND NEW.canonical_bytes IS NULL)
  OR (OLD.canonical_bytes IS NOT NULL AND NEW.canonical_bytes IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'tool outcome blob is immutable');
END;

-- Compaction is only in scope once every operation owning the blob is terminal,
-- so a live invocation can never lose the payload it is still working from.
CREATE TRIGGER IF NOT EXISTS tool_outcome_blobs_compaction_requires_terminal
BEFORE UPDATE OF canonical_bytes ON tool_outcome_blobs
WHEN NEW.canonical_bytes IS NULL
  AND (
      NOT EXISTS (
          SELECT 1 FROM tool_outcomes
          WHERE raw_output_digest = OLD.digest
      )
      OR EXISTS (
          SELECT 1 FROM tool_outcomes o
          JOIN admission_operations a ON a.operation_id = o.operation_id
          WHERE o.raw_output_digest = OLD.digest
            AND a.terminal = 0
      )
  )
BEGIN
    SELECT RAISE(ABORT, 'tool outcome blob is retained while an owning operation is live');
END;

CREATE TRIGGER IF NOT EXISTS tool_outcome_blobs_no_delete
BEFORE DELETE ON tool_outcome_blobs
BEGIN
    SELECT RAISE(ABORT, 'tool outcome blob is immutable');
END;

CREATE TABLE IF NOT EXISTS tool_outcomes (
    operation_id TEXT NOT NULL PRIMARY KEY,
    outcome_id TEXT NOT NULL UNIQUE CHECK (
        length(outcome_id) = 64
        AND outcome_id NOT GLOB '*[^0-9a-f]*'
    ),
    request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 512),
    raw_output_digest TEXT NOT NULL,
    outcome_version INTEGER NOT NULL CHECK (outcome_version > 0),
    lifecycle_digest TEXT NOT NULL CHECK (
        length(lifecycle_digest) = 64
        AND lifecycle_digest NOT GLOB '*[^0-9a-f]*'
    ),
    participant_digest TEXT NOT NULL CHECK (
        length(participant_digest) = 64
        AND participant_digest NOT GLOB '*[^0-9a-f]*'
    ),
    outcome_json BLOB NOT NULL CHECK (length(outcome_json) BETWEEN 1 AND 1048576),
    recorded_at_unix_ms INTEGER NOT NULL CHECK (recorded_at_unix_ms > 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK (
        updated_at_unix_ms >= recorded_at_unix_ms
    ),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    UNIQUE (operation_id, outcome_id),
    FOREIGN KEY (operation_id) REFERENCES admission_operations(operation_id),
    FOREIGN KEY (raw_output_digest) REFERENCES tool_outcome_blobs(digest),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch)
);

CREATE TRIGGER IF NOT EXISTS tool_outcomes_exact_lease_insert
BEFORE INSERT ON tool_outcomes
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'tool outcome has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS tool_outcomes_exact_lease_update
BEFORE UPDATE ON tool_outcomes
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'tool outcome update has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS tool_outcomes_immutable_identity
BEFORE UPDATE ON tool_outcomes
WHEN NEW.operation_id <> OLD.operation_id
  OR NEW.outcome_id <> OLD.outcome_id
  OR NEW.request_id <> OLD.request_id
  OR NEW.raw_output_digest <> OLD.raw_output_digest
  OR NEW.recorded_at_unix_ms <> OLD.recorded_at_unix_ms
BEGIN
    SELECT RAISE(ABORT, 'tool outcome identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS tool_outcomes_versioned_body
BEFORE UPDATE ON tool_outcomes
WHEN NEW.outcome_version <> OLD.outcome_version + 1
BEGIN
    SELECT RAISE(ABORT, 'tool outcome update requires one version increment');
END;

CREATE TRIGGER IF NOT EXISTS tool_outcomes_no_delete
BEFORE DELETE ON tool_outcomes
BEGIN
    SELECT RAISE(ABORT, 'tool outcome must be retained');
END;

CREATE TABLE IF NOT EXISTS post_return_evaluations (
    operation_id TEXT NOT NULL PRIMARY KEY,
    evaluation_id TEXT NOT NULL UNIQUE CHECK (
        length(evaluation_id) = 64
        AND evaluation_id NOT GLOB '*[^0-9a-f]*'
    ),
    outcome_id TEXT NOT NULL,
    evaluation_version INTEGER NOT NULL CHECK (evaluation_version > 0),
    lifecycle_digest TEXT NOT NULL CHECK (
        length(lifecycle_digest) = 64
        AND lifecycle_digest NOT GLOB '*[^0-9a-f]*'
    ),
    participant_digest TEXT NOT NULL CHECK (
        length(participant_digest) = 64
        AND participant_digest NOT GLOB '*[^0-9a-f]*'
    ),
    evaluation_json BLOB NOT NULL CHECK (
        length(evaluation_json) BETWEEN 1 AND 67108864
    ),
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms > 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK (
        updated_at_unix_ms >= created_at_unix_ms
    ),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    FOREIGN KEY (operation_id, outcome_id)
        REFERENCES tool_outcomes(operation_id, outcome_id),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch)
);

CREATE TRIGGER IF NOT EXISTS post_return_evaluations_exact_lease_insert
BEFORE INSERT ON post_return_evaluations
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'post-return evaluation has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS post_return_evaluations_exact_lease_update
BEFORE UPDATE ON post_return_evaluations
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'post-return evaluation update has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS post_return_evaluations_immutable_identity
BEFORE UPDATE ON post_return_evaluations
WHEN NEW.operation_id <> OLD.operation_id
  OR NEW.evaluation_id <> OLD.evaluation_id
  OR NEW.outcome_id <> OLD.outcome_id
  OR NEW.created_at_unix_ms <> OLD.created_at_unix_ms
BEGIN
    SELECT RAISE(ABORT, 'post-return evaluation identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS post_return_evaluations_versioned_body
BEFORE UPDATE ON post_return_evaluations
WHEN NEW.evaluation_version <> OLD.evaluation_version + 1
BEGIN
    SELECT RAISE(ABORT, 'post-return evaluation update requires one version increment');
END;

CREATE TRIGGER IF NOT EXISTS post_return_evaluations_no_delete
BEFORE DELETE ON post_return_evaluations
BEGIN
    SELECT RAISE(ABORT, 'post-return evaluation must be retained');
END;
