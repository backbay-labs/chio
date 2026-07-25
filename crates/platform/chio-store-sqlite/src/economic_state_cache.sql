CREATE TABLE IF NOT EXISTS economic_state_stages (
    batch_id TEXT PRIMARY KEY CHECK (
        length(batch_id) = 64 AND batch_id NOT GLOB '*[^0-9a-f]*'
    ),
    checkpoint_sequence INTEGER NOT NULL CHECK (checkpoint_sequence > 0),
    checkpoint_digest TEXT NOT NULL CHECK (
        length(checkpoint_digest) = 64
        AND checkpoint_digest NOT GLOB '*[^0-9a-f]*'
    ),
    base_view_json BLOB NOT NULL CHECK (length(base_view_json) BETWEEN 1 AND 4194304),
    batch_json BLOB NOT NULL CHECK (length(batch_json) BETWEEN 1 AND 1048576),
    committed_view_json BLOB CHECK (
        committed_view_json IS NULL OR length(committed_view_json) BETWEEN 1 AND 4194304
    ),
    operation_binding_json BLOB CHECK (
        operation_binding_json IS NULL OR length(operation_binding_json) BETWEEN 1 AND 65536
    ),
    descriptor_kind TEXT CHECK (
        descriptor_kind IS NULL OR length(descriptor_kind) BETWEEN 1 AND 128
    ),
    descriptor_key TEXT CHECK (
        descriptor_key IS NULL OR length(descriptor_key) BETWEEN 1 AND 2048
    ),
    descriptor_digest TEXT CHECK (
        descriptor_digest IS NULL OR (
            length(descriptor_digest) = 64
            AND descriptor_digest NOT GLOB '*[^0-9a-f]*'
        )
    ),
    descriptor_json BLOB CHECK (
        descriptor_json IS NULL OR length(descriptor_json) BETWEEN 1 AND 4194304
    ),
    status TEXT NOT NULL CHECK (status IN (
        'db_staged', 'economic_anchor_advanced', 'db_finalized',
        'discarded', 'quarantined'
    )),
    reason TEXT CHECK (reason IS NULL OR length(reason) BETWEEN 1 AND 4096),
    stage_version INTEGER NOT NULL CHECK (stage_version > 0),
    snapshot_digest TEXT NOT NULL CHECK (
        length(snapshot_digest) = 64
        AND snapshot_digest NOT GLOB '*[^0-9a-f]*'
    ),
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms > 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK (
        updated_at_unix_ms >= created_at_unix_ms
    ),
    CHECK (
        (status = 'db_staged' AND committed_view_json IS NULL AND reason IS NULL)
        OR (status IN ('economic_anchor_advanced', 'db_finalized')
            AND committed_view_json IS NOT NULL AND reason IS NULL)
        OR (status IN ('discarded', 'quarantined') AND reason IS NOT NULL)
    ),
    CHECK (
        (descriptor_kind IS NULL AND descriptor_key IS NULL
            AND descriptor_digest IS NULL AND descriptor_json IS NULL)
        OR (descriptor_kind IS NOT NULL AND descriptor_key IS NOT NULL
            AND descriptor_digest IS NOT NULL AND descriptor_json IS NOT NULL)
    ),
    UNIQUE (
        batch_id, checkpoint_sequence, checkpoint_digest,
        descriptor_kind, descriptor_key, descriptor_digest
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS economic_state_stages_descriptor_identity
    ON economic_state_stages(descriptor_kind, descriptor_key)
    WHERE descriptor_kind IS NOT NULL;

CREATE TABLE IF NOT EXISTS economic_state_stage_heads (
    batch_id TEXT NOT NULL,
    resource_key_digest TEXT NOT NULL CHECK (
        length(resource_key_digest) = 64
        AND resource_key_digest NOT GLOB '*[^0-9a-f]*'
    ),
    resource_key_json BLOB NOT NULL CHECK (length(resource_key_json) BETWEEN 1 AND 4096),
    head_digest TEXT NOT NULL CHECK (
        length(head_digest) = 64 AND head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    head_json BLOB NOT NULL CHECK (length(head_json) BETWEEN 1 AND 1048576),
    PRIMARY KEY (batch_id, resource_key_digest),
    UNIQUE (batch_id, resource_key_json),
    FOREIGN KEY (batch_id) REFERENCES economic_state_stages(batch_id)
);

CREATE TABLE IF NOT EXISTS economic_state_heads (
    resource_key_digest TEXT PRIMARY KEY CHECK (
        length(resource_key_digest) = 64
        AND resource_key_digest NOT GLOB '*[^0-9a-f]*'
    ),
    resource_key_json BLOB NOT NULL UNIQUE CHECK (length(resource_key_json) BETWEEN 1 AND 4096),
    head_digest TEXT NOT NULL CHECK (
        length(head_digest) = 64 AND head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    head_json BLOB NOT NULL CHECK (length(head_json) BETWEEN 1 AND 1048576),
    checkpoint_sequence INTEGER NOT NULL CHECK (checkpoint_sequence > 0),
    checkpoint_digest TEXT NOT NULL CHECK (
        length(checkpoint_digest) = 64
        AND checkpoint_digest NOT GLOB '*[^0-9a-f]*'
    ),
    source_batch_id TEXT NOT NULL,
    FOREIGN KEY (source_batch_id, resource_key_digest)
        REFERENCES economic_state_stage_heads(batch_id, resource_key_digest)
);

CREATE TABLE IF NOT EXISTS economic_state_stage_commits (
    batch_id TEXT NOT NULL,
    stage_version INTEGER NOT NULL CHECK (stage_version > 0),
    status TEXT NOT NULL CHECK (status IN (
        'db_staged', 'economic_anchor_advanced', 'db_finalized',
        'discarded', 'quarantined'
    )),
    snapshot_digest TEXT NOT NULL CHECK (
        length(snapshot_digest) = 64
        AND snapshot_digest NOT GLOB '*[^0-9a-f]*'
    ),
    previous_commit_digest TEXT NOT NULL CHECK (
        length(previous_commit_digest) = 64
        AND previous_commit_digest NOT GLOB '*[^0-9a-f]*'
    ),
    commit_digest TEXT NOT NULL CHECK (
        length(commit_digest) = 64
        AND commit_digest NOT GLOB '*[^0-9a-f]*'
    ),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    recorded_at_unix_ms INTEGER NOT NULL CHECK (recorded_at_unix_ms > 0),
    PRIMARY KEY (batch_id, stage_version),
    FOREIGN KEY (batch_id) REFERENCES economic_state_stages(batch_id),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch)
);

CREATE TRIGGER IF NOT EXISTS economic_state_stage_commits_exact_lease
BEFORE INSERT ON economic_state_stage_commits
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'economic stage commit has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS economic_state_stage_commits_immutable
BEFORE UPDATE ON economic_state_stage_commits
BEGIN
    SELECT RAISE(ABORT, 'economic stage commit is immutable');
END;

CREATE TRIGGER IF NOT EXISTS economic_state_stage_commits_no_delete
BEFORE DELETE ON economic_state_stage_commits
BEGIN
    SELECT RAISE(ABORT, 'economic stage commit is immutable');
END;

CREATE TRIGGER IF NOT EXISTS economic_state_stage_heads_immutable
BEFORE UPDATE ON economic_state_stage_heads
BEGIN
    SELECT RAISE(ABORT, 'economic staged head is immutable');
END;

CREATE TRIGGER IF NOT EXISTS economic_state_stage_heads_no_delete
BEFORE DELETE ON economic_state_stage_heads
BEGIN
    SELECT RAISE(ABORT, 'economic staged head is immutable');
END;

CREATE TRIGGER IF NOT EXISTS economic_state_stage_identity_immutable
BEFORE UPDATE OF batch_id, checkpoint_sequence, checkpoint_digest,
    base_view_json, batch_json, operation_binding_json, descriptor_kind,
    descriptor_key, descriptor_digest, descriptor_json, created_at_unix_ms
ON economic_state_stages
BEGIN
    SELECT RAISE(ABORT, 'economic stage identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS economic_state_stage_versioned
BEFORE UPDATE ON economic_state_stages
WHEN NEW.stage_version <> OLD.stage_version + 1
BEGIN
    SELECT RAISE(ABORT, 'economic stage update requires one version increment');
END;

CREATE TRIGGER IF NOT EXISTS economic_state_stage_terminal_immutable
BEFORE UPDATE ON economic_state_stages
WHEN OLD.status IN ('db_finalized', 'discarded', 'quarantined')
BEGIN
    SELECT RAISE(ABORT, 'terminal economic stage is immutable');
END;
