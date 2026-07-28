CREATE TABLE IF NOT EXISTS admission_operations (
    operation_id TEXT NOT NULL PRIMARY KEY
        CHECK (length(operation_id) = 64 AND operation_id NOT GLOB '*[^0-9a-f]*'),
    request_namespace_digest TEXT NOT NULL
        CHECK (length(request_namespace_digest) = 64
               AND request_namespace_digest NOT GLOB '*[^0-9a-f]*'),
    request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 512),
    operation_json BLOB NOT NULL CHECK (length(operation_json) BETWEEN 1 AND 262144),
    state TEXT NOT NULL CHECK (state IN (
        'prepared', 'broker_attempt_registered', 'approval_required',
        'budget_authorized', 'approval_reserved', 'ready_to_dispatch',
        'capture_pending', 'dispatch_committed', 'finalizing', 'completed',
        'compensated_before_dispatch', 'not_accepted_after_dispatch_commit',
        'outcome_unknown_after_dispatch', 'denied_after_delivery', 'mutation_ready',
        'mutation_submitted', 'economic_mutation_applied', 'economic_mutation_not_applied'
    )),
    terminal INTEGER NOT NULL CHECK (terminal IN (0, 1)),
    coordinator_lease_epoch INTEGER NOT NULL CHECK (coordinator_lease_epoch > 0),
    version INTEGER NOT NULL CHECK (version > 0),
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms > 0),
    updated_at_unix_ms INTEGER NOT NULL
        CHECK (updated_at_unix_ms >= created_at_unix_ms),
    recovery_claimant_id TEXT,
    recovery_coordinator_lease_id TEXT,
    recovery_coordinator_lease_epoch INTEGER,
    recovery_claimed_version INTEGER,
    recovery_expires_at_unix_ms INTEGER,
    recovery_store_uuid TEXT,
    recovery_store_lease_id TEXT,
    recovery_store_owner_epoch INTEGER,
    CHECK (
        (recovery_claimant_id IS NULL
         AND recovery_coordinator_lease_id IS NULL
         AND recovery_coordinator_lease_epoch IS NULL
         AND recovery_claimed_version IS NULL
         AND recovery_expires_at_unix_ms IS NULL
         AND recovery_store_uuid IS NULL
         AND recovery_store_lease_id IS NULL
         AND recovery_store_owner_epoch IS NULL)
        OR
        (length(recovery_claimant_id) BETWEEN 1 AND 512
         AND length(recovery_coordinator_lease_id) BETWEEN 1 AND 512
         AND recovery_coordinator_lease_epoch > 0
         AND recovery_claimed_version > 0
         AND recovery_expires_at_unix_ms > 0
         AND recovery_store_uuid <> ''
         AND recovery_store_lease_id <> ''
         AND recovery_store_owner_epoch > 0)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS admission_operations_replay_key
    ON admission_operations(request_namespace_digest, request_id);

CREATE INDEX IF NOT EXISTS admission_operations_recovery
    ON admission_operations(
        terminal, recovery_expires_at_unix_ms, updated_at_unix_ms, operation_id
    );

CREATE TABLE IF NOT EXISTS admission_operation_commit_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    head_sequence INTEGER NOT NULL CHECK (head_sequence >= 0),
    head_chain_digest TEXT NOT NULL CHECK (
        length(head_chain_digest) = 64
        AND head_chain_digest NOT GLOB '*[^0-9a-f]*'
    ),
    trusted_time_high_water_unix_ms INTEGER NOT NULL
        CHECK (trusted_time_high_water_unix_ms >= 0)
);

INSERT INTO admission_operation_commit_meta (
    singleton, head_sequence, head_chain_digest,
    trusted_time_high_water_unix_ms
)
VALUES (
    1, 0,
    '0000000000000000000000000000000000000000000000000000000000000000',
    0
)
ON CONFLICT(singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS admission_operation_commits (
    commit_sequence INTEGER PRIMARY KEY CHECK (commit_sequence > 0),
    operation_id TEXT NOT NULL,
    operation_version INTEGER NOT NULL CHECK (operation_version > 0),
    mutation_kind TEXT NOT NULL CHECK (
        mutation_kind IN (
            'begin', 'compare_and_swap', 'recovery_claim', 'participant_update',
            'channel_reservation_finalized'
        )
    ),
    operation_digest TEXT NOT NULL
        CHECK (length(operation_digest) = 64
               AND operation_digest NOT GLOB '*[^0-9a-f]*'),
    recovery_claim_digest TEXT CHECK (
        recovery_claim_digest IS NULL
        OR (length(recovery_claim_digest) = 64
            AND recovery_claim_digest NOT GLOB '*[^0-9a-f]*')
    ),
    participant_digest TEXT CHECK (
        participant_digest IS NULL
        OR (length(participant_digest) = 64
            AND participant_digest NOT GLOB '*[^0-9a-f]*')
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
    recorded_at_unix_ms INTEGER NOT NULL CHECK (recorded_at_unix_ms > 0),
    FOREIGN KEY (operation_id) REFERENCES admission_operations(operation_id),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch),
    CHECK (
        (mutation_kind = 'begin'
         AND recovery_claim_digest IS NULL)
        OR (mutation_kind = 'recovery_claim'
            AND recovery_claim_digest IS NOT NULL
            AND participant_digest IS NULL)
        OR (mutation_kind = 'compare_and_swap'
            AND recovery_claim_digest IS NOT NULL)
        OR (mutation_kind = 'participant_update'
            AND recovery_claim_digest IS NOT NULL
            AND participant_digest IS NOT NULL)
        OR (mutation_kind = 'channel_reservation_finalized'
            AND recovery_claim_digest IS NOT NULL
            AND participant_digest IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS admission_operation_commits_operation
    ON admission_operation_commits(operation_id, commit_sequence);

CREATE TRIGGER IF NOT EXISTS admission_operation_commits_exact_lease
BEFORE INSERT ON admission_operation_commits
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'admission operation commit has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS admission_operation_commits_immutable
BEFORE UPDATE ON admission_operation_commits
BEGIN
    SELECT RAISE(ABORT, 'admission operation commit is immutable');
END;

CREATE TRIGGER IF NOT EXISTS admission_operation_commits_no_delete
BEFORE DELETE ON admission_operation_commits
BEGIN
    SELECT RAISE(ABORT, 'admission operation commit is immutable');
END;

CREATE TRIGGER IF NOT EXISTS admission_operations_immutable_identity
BEFORE UPDATE OF operation_id, request_namespace_digest, request_id, created_at_unix_ms
ON admission_operations
BEGIN
    SELECT RAISE(ABORT, 'admission operation identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS admission_operations_versioned_body
BEFORE UPDATE ON admission_operations
WHEN (NEW.operation_json <> OLD.operation_json
      OR NEW.state <> OLD.state
      OR NEW.terminal <> OLD.terminal
      OR NEW.coordinator_lease_epoch <> OLD.coordinator_lease_epoch)
     AND NEW.version <> OLD.version + 1
BEGIN
    SELECT RAISE(ABORT, 'admission operation body requires one version increment');
END;

CREATE TRIGGER IF NOT EXISTS admission_operations_terminal_immutable
BEFORE UPDATE ON admission_operations
WHEN OLD.terminal = 1
     AND (NEW.operation_json <> OLD.operation_json
          OR NEW.state <> OLD.state
          OR NEW.terminal <> OLD.terminal
          OR NEW.coordinator_lease_epoch <> OLD.coordinator_lease_epoch
          OR NEW.version <> OLD.version)
BEGIN
    SELECT RAISE(ABORT, 'terminal admission operation is immutable');
END;

CREATE TRIGGER IF NOT EXISTS admission_operations_no_delete
BEFORE DELETE ON admission_operations
BEGIN
    SELECT RAISE(ABORT, 'admission operation must be retained');
END;

CREATE TRIGGER IF NOT EXISTS admission_operations_terminal_no_claim
BEFORE UPDATE ON admission_operations
WHEN OLD.terminal = 1
     AND (NEW.recovery_claimant_id IS NOT OLD.recovery_claimant_id
          OR NEW.recovery_coordinator_lease_id IS NOT OLD.recovery_coordinator_lease_id
          OR NEW.recovery_coordinator_lease_epoch IS NOT OLD.recovery_coordinator_lease_epoch
          OR NEW.recovery_claimed_version IS NOT OLD.recovery_claimed_version
          OR NEW.recovery_expires_at_unix_ms IS NOT OLD.recovery_expires_at_unix_ms
          OR NEW.recovery_store_uuid IS NOT OLD.recovery_store_uuid
          OR NEW.recovery_store_lease_id IS NOT OLD.recovery_store_lease_id
          OR NEW.recovery_store_owner_epoch IS NOT OLD.recovery_store_owner_epoch)
BEGIN
    SELECT RAISE(ABORT, 'terminal admission operation cannot be recovery-claimed');
END;

CREATE TABLE IF NOT EXISTS threshold_approval_proposals (
    proposal_id TEXT NOT NULL PRIMARY KEY CHECK (length(proposal_id) BETWEEN 1 AND 512),
    operation_id TEXT NOT NULL UNIQUE,
    request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 512),
    governed_intent_hash TEXT NOT NULL CHECK (
        length(governed_intent_hash) = 64
        AND governed_intent_hash NOT GLOB '*[^0-9a-f]*'
    ),
    subject_fingerprint TEXT NOT NULL CHECK (subject_fingerprint <> ''),
    authorizing_capability_digest TEXT NOT NULL CHECK (
        length(authorizing_capability_digest) = 64
        AND authorizing_capability_digest NOT GLOB '*[^0-9a-f]*'
    ),
    policy_hash TEXT NOT NULL CHECK (
        length(policy_hash) = 64 AND policy_hash NOT GLOB '*[^0-9a-f]*'
    ),
    threshold INTEGER NOT NULL CHECK (threshold > 0),
    eligible_set_digest TEXT NOT NULL CHECK (
        length(eligible_set_digest) = 64
        AND eligible_set_digest NOT GLOB '*[^0-9a-f]*'
    ),
    proposal_created_at INTEGER NOT NULL CHECK (proposal_created_at >= 0),
    proposal_deadline INTEGER NOT NULL CHECK (proposal_deadline > proposal_created_at),
    proposal_hash TEXT NOT NULL UNIQUE CHECK (
        length(proposal_hash) = 64 AND proposal_hash NOT GLOB '*[^0-9a-f]*'
    ),
    approval_set_hash TEXT NOT NULL UNIQUE CHECK (
        length(approval_set_hash) = 64
        AND approval_set_hash NOT GLOB '*[^0-9a-f]*'
    ),
    proposal_json BLOB NOT NULL CHECK (length(proposal_json) BETWEEN 1 AND 262144),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'committed', 'cancelled')),
    reserved_at_unix_ms INTEGER NOT NULL CHECK (reserved_at_unix_ms > 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= reserved_at_unix_ms),
    FOREIGN KEY (operation_id) REFERENCES admission_operations(operation_id)
);

CREATE TABLE IF NOT EXISTS threshold_approval_tokens (
    proposal_id TEXT NOT NULL,
    token_id TEXT NOT NULL CHECK (length(token_id) BETWEEN 1 AND 512),
    approver_fingerprint TEXT NOT NULL CHECK (approver_fingerprint <> ''),
    canonical_token_digest TEXT NOT NULL UNIQUE CHECK (
        length(canonical_token_digest) = 64
        AND canonical_token_digest NOT GLOB '*[^0-9a-f]*'
    ),
    token_json BLOB NOT NULL CHECK (length(token_json) BETWEEN 1 AND 262144),
    PRIMARY KEY (proposal_id, token_id),
    UNIQUE (proposal_id, approver_fingerprint),
    UNIQUE (proposal_id, canonical_token_digest),
    FOREIGN KEY (proposal_id) REFERENCES threshold_approval_proposals(proposal_id)
);

CREATE TRIGGER IF NOT EXISTS threshold_approval_proposals_immutable
BEFORE UPDATE ON threshold_approval_proposals
WHEN NEW.proposal_id <> OLD.proposal_id
     OR NEW.operation_id <> OLD.operation_id
     OR NEW.request_id <> OLD.request_id
     OR NEW.governed_intent_hash <> OLD.governed_intent_hash
     OR NEW.subject_fingerprint <> OLD.subject_fingerprint
     OR NEW.authorizing_capability_digest <> OLD.authorizing_capability_digest
     OR NEW.policy_hash <> OLD.policy_hash
     OR NEW.threshold <> OLD.threshold
     OR NEW.eligible_set_digest <> OLD.eligible_set_digest
     OR NEW.proposal_created_at <> OLD.proposal_created_at
     OR NEW.proposal_deadline <> OLD.proposal_deadline
     OR NEW.proposal_hash <> OLD.proposal_hash
     OR NEW.approval_set_hash <> OLD.approval_set_hash
     OR NEW.proposal_json <> OLD.proposal_json
     OR NEW.reserved_at_unix_ms <> OLD.reserved_at_unix_ms
BEGIN
    SELECT RAISE(ABORT, 'threshold approval proposal is immutable');
END;

CREATE TRIGGER IF NOT EXISTS threshold_approval_proposals_terminal
BEFORE UPDATE OF state ON threshold_approval_proposals
WHEN OLD.state IN ('committed', 'cancelled') AND NEW.state <> OLD.state
BEGIN
    SELECT RAISE(ABORT, 'terminal threshold approval proposal is immutable');
END;

CREATE TRIGGER IF NOT EXISTS threshold_approval_proposals_lifecycle
BEFORE UPDATE ON threshold_approval_proposals
WHEN NEW.updated_at_unix_ms < OLD.updated_at_unix_ms
     OR (NEW.state = OLD.state AND NEW.updated_at_unix_ms <> OLD.updated_at_unix_ms)
     OR (OLD.state = 'reserved' AND NEW.state NOT IN ('reserved', 'committed', 'cancelled'))
BEGIN
    SELECT RAISE(ABORT, 'invalid threshold approval proposal lifecycle');
END;

CREATE TRIGGER IF NOT EXISTS threshold_approval_proposals_no_delete
BEFORE DELETE ON threshold_approval_proposals
BEGIN
    SELECT RAISE(ABORT, 'threshold approval proposal is a replay tombstone');
END;

CREATE TRIGGER IF NOT EXISTS threshold_approval_tokens_immutable
BEFORE UPDATE ON threshold_approval_tokens
BEGIN
    SELECT RAISE(ABORT, 'threshold approval token is immutable');
END;

CREATE TRIGGER IF NOT EXISTS threshold_approval_tokens_no_delete
BEFORE DELETE ON threshold_approval_tokens
BEGIN
    SELECT RAISE(ABORT, 'threshold approval token is a replay tombstone');
END;

CREATE TRIGGER IF NOT EXISTS admission_operations_commit_threshold_approval
AFTER UPDATE OF state ON admission_operations
WHEN NEW.state IN (
    'dispatch_committed', 'finalizing', 'completed',
    'not_accepted_after_dispatch_commit', 'outcome_unknown_after_dispatch'
)
BEGIN
    UPDATE threshold_approval_proposals
    SET state = 'committed', updated_at_unix_ms = NEW.updated_at_unix_ms
    WHERE operation_id = NEW.operation_id AND state = 'reserved';
END;

CREATE TRIGGER IF NOT EXISTS admission_operations_cancel_threshold_approval
AFTER UPDATE OF state ON admission_operations
WHEN NEW.state = 'compensated_before_dispatch'
BEGIN
    UPDATE threshold_approval_proposals
    SET state = 'cancelled', updated_at_unix_ms = NEW.updated_at_unix_ms
    WHERE operation_id = NEW.operation_id AND state = 'reserved';
END;

CREATE TABLE IF NOT EXISTS admission_operation_terminal_projections (
    operation_id TEXT NOT NULL PRIMARY KEY,
    source_operation_version INTEGER NOT NULL CHECK (source_operation_version > 0),
    terminal_operation_version INTEGER NOT NULL CHECK (
        terminal_operation_version = source_operation_version + 1
    ),
    terminal_state TEXT NOT NULL CHECK (terminal_state IN (
        'completed', 'compensated_before_dispatch',
        'not_accepted_after_dispatch_commit', 'outcome_unknown_after_dispatch',
        'denied_after_delivery',
        'economic_mutation_applied', 'economic_mutation_not_applied'
    )),
    projection_body_digest TEXT NOT NULL CHECK (
        length(projection_body_digest) = 64
        AND projection_body_digest NOT GLOB '*[^0-9a-f]*'
    ),
    projection_digest TEXT NOT NULL CHECK (
        length(projection_digest) = 64
        AND projection_digest NOT GLOB '*[^0-9a-f]*'
    ),
    projection_json BLOB NOT NULL CHECK (
        length(projection_json) BETWEEN 1 AND 4194304
    ),
    manifest_json BLOB NOT NULL CHECK (
        length(manifest_json) BETWEEN 1 AND 262144
    ),
    record_count INTEGER NOT NULL CHECK (record_count BETWEEN 1 AND 32),
    committed_at_unix_ms INTEGER NOT NULL CHECK (committed_at_unix_ms > 0),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    FOREIGN KEY (operation_id) REFERENCES admission_operations(operation_id),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch)
);

CREATE TRIGGER IF NOT EXISTS admission_operation_terminal_projections_exact_lease
BEFORE INSERT ON admission_operation_terminal_projections
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'admission terminal projection has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS admission_operation_terminal_projections_immutable
BEFORE UPDATE ON admission_operation_terminal_projections
BEGIN
    SELECT RAISE(ABORT, 'admission terminal projection is immutable');
END;

CREATE TRIGGER IF NOT EXISTS admission_operation_terminal_projections_no_delete
BEFORE DELETE ON admission_operation_terminal_projections
BEGIN
    SELECT RAISE(ABORT, 'admission terminal projection is immutable');
END;

CREATE TABLE IF NOT EXISTS admission_operation_terminal_records (
    operation_id TEXT NOT NULL,
    record_kind TEXT NOT NULL CHECK (record_kind IN (
        'receipt', 'incident', 'tool_outcome', 'payment_terminal',
        'authorization_consumption', 'outcome_eligibility',
        'observation_attempt_zero', 'obligation', 'release_proof',
        'channel_terminal', 'economic_mutation_result', 'mutation_audit'
    )),
    record_id TEXT NOT NULL CHECK (length(record_id) BETWEEN 1 AND 512),
    record_digest TEXT NOT NULL CHECK (
        length(record_digest) = 64
        AND record_digest NOT GLOB '*[^0-9a-f]*'
    ),
    record_json BLOB NOT NULL CHECK (length(record_json) BETWEEN 1 AND 1048576),
    PRIMARY KEY (operation_id, record_kind, record_id),
    UNIQUE (record_kind, record_id),
    FOREIGN KEY (operation_id)
        REFERENCES admission_operation_terminal_projections(operation_id)
);

CREATE INDEX IF NOT EXISTS admission_operation_terminal_records_kind
    ON admission_operation_terminal_records(record_kind, operation_id);

CREATE TRIGGER IF NOT EXISTS admission_operation_terminal_records_immutable
BEFORE UPDATE ON admission_operation_terminal_records
BEGIN
    SELECT RAISE(ABORT, 'admission terminal record is immutable');
END;

CREATE TRIGGER IF NOT EXISTS admission_operation_terminal_records_no_delete
BEFORE DELETE ON admission_operation_terminal_records
BEGIN
    SELECT RAISE(ABORT, 'admission terminal record is immutable');
END;

CREATE TABLE IF NOT EXISTS obligation_atoms (
    obligation_id TEXT NOT NULL PRIMARY KEY CHECK (
        length(obligation_id) = 64
        AND obligation_id NOT GLOB '*[^0-9a-f]*'
    ),
    operation_id TEXT NOT NULL UNIQUE,
    atom_digest TEXT NOT NULL UNIQUE CHECK (
        length(atom_digest) = 64
        AND atom_digest NOT GLOB '*[^0-9a-f]*'
    ),
    source_receipt_id TEXT NOT NULL UNIQUE CHECK (
        length(source_receipt_id) BETWEEN 1 AND 512
    ),
    source_receipt_digest TEXT NOT NULL UNIQUE CHECK (
        length(source_receipt_digest) = 64
        AND source_receipt_digest NOT GLOB '*[^0-9a-f]*'
    ),
    atom_json BLOB NOT NULL CHECK (length(atom_json) BETWEEN 1 AND 1048576),
    committed_at_unix_ms INTEGER NOT NULL CHECK (committed_at_unix_ms > 0),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    UNIQUE (obligation_id, atom_digest),
    FOREIGN KEY (operation_id)
        REFERENCES admission_operation_terminal_projections(operation_id),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch)
);

CREATE TRIGGER IF NOT EXISTS obligation_atoms_exact_lease
BEFORE INSERT ON obligation_atoms
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'obligation atom has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS obligation_atoms_immutable
BEFORE UPDATE ON obligation_atoms
BEGIN
    SELECT RAISE(ABORT, 'obligation atom is immutable');
END;

CREATE TRIGGER IF NOT EXISTS obligation_atoms_no_delete
BEFORE DELETE ON obligation_atoms
BEGIN
    SELECT RAISE(ABORT, 'obligation atom is immutable');
END;

CREATE TABLE IF NOT EXISTS obligation_disposition_records (
    obligation_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    lifecycle_fence INTEGER NOT NULL CHECK (lifecycle_fence = version),
    atom_digest TEXT NOT NULL CHECK (
        length(atom_digest) = 64
        AND atom_digest NOT GLOB '*[^0-9a-f]*'
    ),
    disposition_digest TEXT NOT NULL UNIQUE CHECK (
        length(disposition_digest) = 64
        AND disposition_digest NOT GLOB '*[^0-9a-f]*'
    ),
    operation_id TEXT NOT NULL,
    record_json BLOB NOT NULL CHECK (length(record_json) BETWEEN 1 AND 1048576),
    committed_at_unix_ms INTEGER NOT NULL CHECK (committed_at_unix_ms > 0),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    PRIMARY KEY (obligation_id, version),
    FOREIGN KEY (obligation_id, atom_digest)
        REFERENCES obligation_atoms(obligation_id, atom_digest),
    FOREIGN KEY (operation_id)
        REFERENCES admission_operations(operation_id),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch)
);

CREATE INDEX IF NOT EXISTS obligation_disposition_records_operation
    ON obligation_disposition_records(operation_id, obligation_id, version);

CREATE TRIGGER IF NOT EXISTS obligation_disposition_records_exact_lease
BEFORE INSERT ON obligation_disposition_records
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'obligation disposition has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS obligation_disposition_records_immutable
BEFORE UPDATE ON obligation_disposition_records
BEGIN
    SELECT RAISE(ABORT, 'obligation disposition record is immutable');
END;

CREATE TRIGGER IF NOT EXISTS obligation_disposition_records_no_delete
BEFORE DELETE ON obligation_disposition_records
BEGIN
    SELECT RAISE(ABORT, 'obligation disposition record is immutable');
END;

CREATE TABLE IF NOT EXISTS obligation_settlement_lifecycle_records (
    obligation_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    lifecycle_fence INTEGER NOT NULL CHECK (lifecycle_fence = version),
    atom_digest TEXT NOT NULL CHECK (
        length(atom_digest) = 64
        AND atom_digest NOT GLOB '*[^0-9a-f]*'
    ),
    lifecycle_digest TEXT NOT NULL UNIQUE CHECK (
        length(lifecycle_digest) = 64
        AND lifecycle_digest NOT GLOB '*[^0-9a-f]*'
    ),
    operation_id TEXT NOT NULL,
    record_json BLOB NOT NULL CHECK (length(record_json) BETWEEN 1 AND 1048576),
    committed_at_unix_ms INTEGER NOT NULL CHECK (committed_at_unix_ms > 0),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    PRIMARY KEY (obligation_id, version),
    FOREIGN KEY (obligation_id, atom_digest)
        REFERENCES obligation_atoms(obligation_id, atom_digest),
    FOREIGN KEY (operation_id)
        REFERENCES admission_operations(operation_id),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch)
);

CREATE INDEX IF NOT EXISTS obligation_settlement_lifecycle_records_operation
    ON obligation_settlement_lifecycle_records(operation_id, obligation_id, version);

CREATE TRIGGER IF NOT EXISTS obligation_settlement_lifecycle_records_exact_lease
BEFORE INSERT ON obligation_settlement_lifecycle_records
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'obligation settlement lifecycle has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS obligation_settlement_lifecycle_records_immutable
BEFORE UPDATE ON obligation_settlement_lifecycle_records
BEGIN
    SELECT RAISE(ABORT, 'obligation settlement lifecycle record is immutable');
END;

CREATE TRIGGER IF NOT EXISTS obligation_settlement_lifecycle_records_no_delete
BEFORE DELETE ON obligation_settlement_lifecycle_records
BEGIN
    SELECT RAISE(ABORT, 'obligation settlement lifecycle record is immutable');
END;

CREATE TABLE IF NOT EXISTS obligation_head_commits (
    obligation_id TEXT NOT NULL,
    head_sequence INTEGER NOT NULL CHECK (head_sequence > 0),
    previous_head_digest TEXT NOT NULL CHECK (
        length(previous_head_digest) = 64
        AND previous_head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    head_digest TEXT NOT NULL CHECK (
        length(head_digest) = 64
        AND head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    atom_digest TEXT NOT NULL CHECK (
        length(atom_digest) = 64
        AND atom_digest NOT GLOB '*[^0-9a-f]*'
    ),
    disposition_version INTEGER NOT NULL CHECK (disposition_version > 0),
    disposition_lifecycle_fence INTEGER NOT NULL CHECK (
        disposition_lifecycle_fence = disposition_version
    ),
    disposition_digest TEXT NOT NULL CHECK (
        length(disposition_digest) = 64
        AND disposition_digest NOT GLOB '*[^0-9a-f]*'
    ),
    settlement_version INTEGER NOT NULL CHECK (settlement_version > 0),
    settlement_lifecycle_fence INTEGER NOT NULL CHECK (
        settlement_lifecycle_fence = settlement_version
    ),
    settlement_lifecycle_digest TEXT NOT NULL CHECK (
        length(settlement_lifecycle_digest) = 64
        AND settlement_lifecycle_digest NOT GLOB '*[^0-9a-f]*'
    ),
    snapshot_version INTEGER NOT NULL CHECK (snapshot_version > 0),
    resource_fence INTEGER NOT NULL CHECK (resource_fence > 0),
    source_kind TEXT NOT NULL CHECK (source_kind IN (
        'initial_projection', 'disposition_transition', 'settlement_lifecycle'
    )),
    source_operation_id TEXT NOT NULL,
    participant_digest TEXT CHECK (
        participant_digest IS NULL
        OR (length(participant_digest) = 64
            AND participant_digest NOT GLOB '*[^0-9a-f]*')
    ),
    participant_commit_sequence INTEGER CHECK (
        participant_commit_sequence IS NULL OR participant_commit_sequence > 0
    ),
    committed_at_unix_ms INTEGER NOT NULL CHECK (committed_at_unix_ms > 0),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    PRIMARY KEY (obligation_id, head_sequence),
    UNIQUE (obligation_id, head_digest),
    UNIQUE (obligation_id, head_sequence, head_digest),
    CHECK ((participant_digest IS NULL) = (participant_commit_sequence IS NULL)),
    FOREIGN KEY (obligation_id, atom_digest)
        REFERENCES obligation_atoms(obligation_id, atom_digest),
    FOREIGN KEY (obligation_id, disposition_version)
        REFERENCES obligation_disposition_records(obligation_id, version),
    FOREIGN KEY (obligation_id, settlement_version)
        REFERENCES obligation_settlement_lifecycle_records(obligation_id, version),
    FOREIGN KEY (source_operation_id)
        REFERENCES admission_operations(operation_id),
    FOREIGN KEY (participant_commit_sequence)
        REFERENCES admission_operation_commits(commit_sequence),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch)
);

CREATE INDEX IF NOT EXISTS obligation_head_commits_operation
    ON obligation_head_commits(source_operation_id, obligation_id, head_sequence);

CREATE UNIQUE INDEX IF NOT EXISTS obligation_head_commits_participant
    ON obligation_head_commits(participant_commit_sequence)
    WHERE participant_commit_sequence IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS obligation_head_commits_source_operation
    ON obligation_head_commits(source_operation_id)
    WHERE source_kind <> 'initial_projection';

CREATE TRIGGER IF NOT EXISTS obligation_head_commits_exact_lease
BEFORE INSERT ON obligation_head_commits
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'obligation head commit has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS obligation_head_commits_predecessor
BEFORE INSERT ON obligation_head_commits
WHEN (
    NEW.head_sequence = 1
    AND (
        NEW.previous_head_digest <>
            '0000000000000000000000000000000000000000000000000000000000000000'
        OR NEW.snapshot_version <> 1
        OR NEW.resource_fence <> 1
        OR NEW.source_kind <> 'initial_projection'
        OR NEW.participant_digest IS NOT NULL
        OR NEW.participant_commit_sequence IS NOT NULL
        OR EXISTS (
            SELECT 1 FROM obligation_heads
            WHERE obligation_id = NEW.obligation_id
        )
    )
)
OR (
    NEW.head_sequence > 1
    AND (
        NEW.source_kind = 'initial_projection'
        OR NEW.participant_digest IS NULL
        OR NEW.participant_commit_sequence IS NULL
        OR NOT EXISTS (
            SELECT 1
            FROM obligation_head_commits AS previous
            JOIN obligation_heads AS current
              ON current.obligation_id = previous.obligation_id
             AND current.head_sequence = previous.head_sequence
             AND current.head_digest = previous.head_digest
            WHERE previous.obligation_id = NEW.obligation_id
              AND previous.head_sequence = NEW.head_sequence - 1
              AND previous.head_digest = NEW.previous_head_digest
              AND NEW.snapshot_version = previous.snapshot_version + 1
              AND NEW.resource_fence = previous.resource_fence + 1
              AND NEW.disposition_version BETWEEN previous.disposition_version
                                                  AND previous.disposition_version + 1
              AND NEW.settlement_version BETWEEN previous.settlement_version
                                               AND previous.settlement_version + 1
              AND (NEW.disposition_version <> previous.disposition_version
                   OR NEW.settlement_version <> previous.settlement_version)
              AND NEW.committed_at_unix_ms >= previous.committed_at_unix_ms
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'obligation head commit lacks its exact predecessor');
END;

CREATE TRIGGER IF NOT EXISTS obligation_head_commits_participant
BEFORE INSERT ON obligation_head_commits
WHEN NEW.head_sequence > 1
 AND NOT EXISTS (
    SELECT 1 FROM admission_operation_commits AS committed
    WHERE committed.commit_sequence = NEW.participant_commit_sequence
      AND committed.operation_id = NEW.source_operation_id
      AND committed.mutation_kind = 'participant_update'
      AND committed.participant_digest = NEW.participant_digest
      AND committed.recorded_at_unix_ms = NEW.committed_at_unix_ms
      AND committed.store_uuid = NEW.store_uuid
      AND committed.store_lease_id = NEW.store_lease_id
      AND committed.store_owner_epoch = NEW.store_owner_epoch
)
BEGIN
    SELECT RAISE(ABORT, 'obligation head commit lacks its admission participant commit');
END;

CREATE TRIGGER IF NOT EXISTS obligation_head_commits_immutable
BEFORE UPDATE ON obligation_head_commits
BEGIN
    SELECT RAISE(ABORT, 'obligation head commit is immutable');
END;

CREATE TRIGGER IF NOT EXISTS obligation_head_commits_no_delete
BEFORE DELETE ON obligation_head_commits
BEGIN
    SELECT RAISE(ABORT, 'obligation head commit is immutable');
END;

CREATE TABLE IF NOT EXISTS obligation_heads (
    obligation_id TEXT NOT NULL PRIMARY KEY,
    head_sequence INTEGER NOT NULL CHECK (head_sequence > 0),
    head_digest TEXT NOT NULL CHECK (
        length(head_digest) = 64
        AND head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    atom_digest TEXT NOT NULL CHECK (
        length(atom_digest) = 64
        AND atom_digest NOT GLOB '*[^0-9a-f]*'
    ),
    disposition_version INTEGER NOT NULL CHECK (disposition_version > 0),
    disposition_lifecycle_fence INTEGER NOT NULL CHECK (
        disposition_lifecycle_fence = disposition_version
    ),
    settlement_version INTEGER NOT NULL CHECK (settlement_version > 0),
    settlement_lifecycle_fence INTEGER NOT NULL CHECK (
        settlement_lifecycle_fence = settlement_version
    ),
    snapshot_version INTEGER NOT NULL CHECK (snapshot_version > 0),
    resource_fence INTEGER NOT NULL CHECK (resource_fence > 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms > 0),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    FOREIGN KEY (obligation_id, head_sequence, head_digest)
        REFERENCES obligation_head_commits(obligation_id, head_sequence, head_digest),
    FOREIGN KEY (obligation_id, atom_digest)
        REFERENCES obligation_atoms(obligation_id, atom_digest),
    FOREIGN KEY (obligation_id, disposition_version)
        REFERENCES obligation_disposition_records(obligation_id, version),
    FOREIGN KEY (obligation_id, settlement_version)
        REFERENCES obligation_settlement_lifecycle_records(obligation_id, version),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch)
);

CREATE TRIGGER IF NOT EXISTS obligation_heads_exact_lease_insert
BEFORE INSERT ON obligation_heads
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'obligation head has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS obligation_heads_committed_insert
BEFORE INSERT ON obligation_heads
WHEN NOT EXISTS (
    SELECT 1 FROM obligation_head_commits AS committed
    WHERE committed.obligation_id = NEW.obligation_id
      AND committed.head_sequence = NEW.head_sequence
      AND committed.head_digest = NEW.head_digest
      AND committed.atom_digest = NEW.atom_digest
      AND committed.disposition_version = NEW.disposition_version
      AND committed.disposition_lifecycle_fence = NEW.disposition_lifecycle_fence
      AND committed.settlement_version = NEW.settlement_version
      AND committed.settlement_lifecycle_fence = NEW.settlement_lifecycle_fence
      AND committed.snapshot_version = NEW.snapshot_version
      AND committed.resource_fence = NEW.resource_fence
      AND committed.committed_at_unix_ms = NEW.updated_at_unix_ms
      AND committed.store_uuid = NEW.store_uuid
      AND committed.store_lease_id = NEW.store_lease_id
      AND committed.store_owner_epoch = NEW.store_owner_epoch
)
BEGIN
    SELECT RAISE(ABORT, 'obligation head lacks its immutable commit');
END;

CREATE TRIGGER IF NOT EXISTS obligation_heads_exact_lease_update
BEFORE UPDATE ON obligation_heads
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'obligation head has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS obligation_heads_versioned
BEFORE UPDATE ON obligation_heads
WHEN NEW.obligation_id <> OLD.obligation_id
  OR NEW.head_sequence <> OLD.head_sequence + 1
  OR NEW.head_digest = OLD.head_digest
  OR NEW.atom_digest <> OLD.atom_digest
  OR NEW.snapshot_version <> OLD.snapshot_version + 1
  OR NEW.resource_fence <> OLD.resource_fence + 1
  OR NEW.disposition_version < OLD.disposition_version
  OR NEW.disposition_version > OLD.disposition_version + 1
  OR NEW.settlement_version < OLD.settlement_version
  OR NEW.settlement_version > OLD.settlement_version + 1
  OR (NEW.disposition_version = OLD.disposition_version
      AND NEW.settlement_version = OLD.settlement_version)
  OR NEW.updated_at_unix_ms < OLD.updated_at_unix_ms
  OR NOT EXISTS (
      SELECT 1 FROM obligation_head_commits AS committed
      WHERE committed.obligation_id = NEW.obligation_id
        AND committed.head_sequence = NEW.head_sequence
        AND committed.head_digest = NEW.head_digest
        AND committed.previous_head_digest = OLD.head_digest
        AND committed.atom_digest = NEW.atom_digest
        AND committed.disposition_version = NEW.disposition_version
        AND committed.disposition_lifecycle_fence = NEW.disposition_lifecycle_fence
        AND committed.settlement_version = NEW.settlement_version
        AND committed.settlement_lifecycle_fence = NEW.settlement_lifecycle_fence
        AND committed.snapshot_version = NEW.snapshot_version
        AND committed.resource_fence = NEW.resource_fence
        AND committed.committed_at_unix_ms = NEW.updated_at_unix_ms
        AND committed.store_uuid = NEW.store_uuid
        AND committed.store_lease_id = NEW.store_lease_id
        AND committed.store_owner_epoch = NEW.store_owner_epoch
  )
BEGIN
    SELECT RAISE(ABORT, 'obligation head requires one fenced state advance');
END;

CREATE TRIGGER IF NOT EXISTS obligation_heads_no_delete
BEFORE DELETE ON obligation_heads
BEGIN
    SELECT RAISE(ABORT, 'obligation head must be retained');
END;

CREATE TABLE IF NOT EXISTS factor_assignment_authority_sets (
    generation INTEGER NOT NULL PRIMARY KEY CHECK (generation > 0),
    active_set_digest TEXT NOT NULL CHECK (
        length(active_set_digest) = 64
        AND active_set_digest NOT GLOB '*[^0-9a-f]*'
    ),
    previous_active_set_digest TEXT CHECK (
        previous_active_set_digest IS NULL
        OR (length(previous_active_set_digest) = 64
            AND previous_active_set_digest NOT GLOB '*[^0-9a-f]*')
    ),
    activated_at_unix_ms INTEGER NOT NULL CHECK (activated_at_unix_ms > 0),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    UNIQUE (generation, active_set_digest),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch)
);

CREATE TRIGGER IF NOT EXISTS factor_assignment_authority_sets_exact_lease
BEFORE INSERT ON factor_assignment_authority_sets
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'factor assignment authority set has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS factor_assignment_authority_sets_linear
BEFORE INSERT ON factor_assignment_authority_sets
WHEN NEW.generation <> COALESCE(
        (SELECT MAX(generation) + 1 FROM factor_assignment_authority_sets),
        1
     )
  OR (NEW.generation = 1 AND NEW.previous_active_set_digest IS NOT NULL)
  OR (NEW.generation > 1 AND NEW.previous_active_set_digest IS NOT (
        SELECT active_set_digest
        FROM factor_assignment_authority_sets
        ORDER BY generation DESC
        LIMIT 1
     ))
  OR NEW.activated_at_unix_ms < COALESCE(
        (SELECT activated_at_unix_ms
         FROM factor_assignment_authority_sets
         ORDER BY generation DESC
         LIMIT 1),
        0
     )
BEGIN
    SELECT RAISE(ABORT, 'factor assignment authority set is not a linear successor');
END;

CREATE TRIGGER IF NOT EXISTS factor_assignment_authority_sets_immutable
BEFORE UPDATE ON factor_assignment_authority_sets
BEGIN
    SELECT RAISE(ABORT, 'factor assignment authority set is immutable');
END;

CREATE TRIGGER IF NOT EXISTS factor_assignment_authority_sets_no_delete
BEFORE DELETE ON factor_assignment_authority_sets
BEGIN
    SELECT RAISE(ABORT, 'factor assignment authority set is immutable');
END;

CREATE TABLE IF NOT EXISTS obligation_assignment_results (
    operation_id TEXT NOT NULL PRIMARY KEY CHECK (
        length(operation_id) = 64
        AND operation_id NOT GLOB '*[^0-9a-f]*'
    ),
    obligation_id TEXT NOT NULL CHECK (
        length(obligation_id) = 64
        AND obligation_id NOT GLOB '*[^0-9a-f]*'
    ),
    obligation_atom_digest TEXT NOT NULL CHECK (
        length(obligation_atom_digest) = 64
        AND obligation_atom_digest NOT GLOB '*[^0-9a-f]*'
    ),
    outcome TEXT NOT NULL CHECK (outcome IN ('applied', 'not_applied')),
    authority_set_generation INTEGER NOT NULL CHECK (authority_set_generation > 0),
    authority_set_digest TEXT NOT NULL CHECK (
        length(authority_set_digest) = 64
        AND authority_set_digest NOT GLOB '*[^0-9a-f]*'
    ),
    authority_configuration_digest TEXT NOT NULL CHECK (
        length(authority_configuration_digest) = 64
        AND authority_configuration_digest NOT GLOB '*[^0-9a-f]*'
    ),
    normalized_request_digest TEXT NOT NULL CHECK (
        length(normalized_request_digest) = 64
        AND normalized_request_digest NOT GLOB '*[^0-9a-f]*'
    ),
    normalized_request_json BLOB NOT NULL CHECK (
        typeof(normalized_request_json) = 'blob'
        AND length(normalized_request_json) BETWEEN 1 AND 1048576
    ),
    claim_digest TEXT NOT NULL CHECK (
        length(claim_digest) = 64
        AND claim_digest NOT GLOB '*[^0-9a-f]*'
    ),
    claim_json BLOB NOT NULL CHECK (
        typeof(claim_json) = 'blob'
        AND length(claim_json) BETWEEN 1 AND 1048576
    ),
    receipt_digest TEXT NOT NULL CHECK (
        length(receipt_digest) = 64
        AND receipt_digest NOT GLOB '*[^0-9a-f]*'
    ),
    receipt_json BLOB NOT NULL CHECK (
        typeof(receipt_json) = 'blob'
        AND length(receipt_json) BETWEEN 1 AND 1048576
    ),
    iou_digest TEXT NOT NULL CHECK (
        length(iou_digest) = 64
        AND iou_digest NOT GLOB '*[^0-9a-f]*'
    ),
    iou_json BLOB NOT NULL CHECK (
        typeof(iou_json) = 'blob'
        AND length(iou_json) BETWEEN 1 AND 1048576
    ),
    offer_digest TEXT NOT NULL CHECK (
        length(offer_digest) = 64
        AND offer_digest NOT GLOB '*[^0-9a-f]*'
    ),
    offer_json BLOB NOT NULL CHECK (
        typeof(offer_json) = 'blob'
        AND length(offer_json) BETWEEN 1 AND 1048576
    ),
    bind_authorization_body_digest TEXT NOT NULL CHECK (
        length(bind_authorization_body_digest) = 64
        AND bind_authorization_body_digest NOT GLOB '*[^0-9a-f]*'
    ),
    bind_authorization_envelope_digest TEXT NOT NULL CHECK (
        length(bind_authorization_envelope_digest) = 64
        AND bind_authorization_envelope_digest NOT GLOB '*[^0-9a-f]*'
    ),
    bind_authorization_json BLOB NOT NULL CHECK (
        typeof(bind_authorization_json) = 'blob'
        AND length(bind_authorization_json) BETWEEN 1 AND 1048576
    ),
    agreement_body_digest TEXT NOT NULL CHECK (
        length(agreement_body_digest) = 64
        AND agreement_body_digest NOT GLOB '*[^0-9a-f]*'
    ),
    agreement_artifact_digest TEXT NOT NULL CHECK (
        length(agreement_artifact_digest) = 64
        AND agreement_artifact_digest NOT GLOB '*[^0-9a-f]*'
    ),
    agreement_seller_signature_digest TEXT NOT NULL CHECK (
        length(agreement_seller_signature_digest) = 64
        AND agreement_seller_signature_digest NOT GLOB '*[^0-9a-f]*'
    ),
    agreement_buyer_signature_digest TEXT NOT NULL CHECK (
        length(agreement_buyer_signature_digest) = 64
        AND agreement_buyer_signature_digest NOT GLOB '*[^0-9a-f]*'
    ),
    agreement_json BLOB NOT NULL CHECK (
        typeof(agreement_json) = 'blob'
        AND length(agreement_json) BETWEEN 1 AND 1048576
    ),
    assignment_authorization_set_digest TEXT NOT NULL CHECK (
        length(assignment_authorization_set_digest) = 64
        AND assignment_authorization_set_digest NOT GLOB '*[^0-9a-f]*'
    ),
    status_proof_body_digest TEXT NOT NULL CHECK (
        length(status_proof_body_digest) = 64
        AND status_proof_body_digest NOT GLOB '*[^0-9a-f]*'
    ),
    status_proof_envelope_digest TEXT NOT NULL CHECK (
        length(status_proof_envelope_digest) = 64
        AND status_proof_envelope_digest NOT GLOB '*[^0-9a-f]*'
    ),
    status_proof_json BLOB NOT NULL CHECK (
        typeof(status_proof_json) = 'blob'
        AND length(status_proof_json) BETWEEN 1 AND 1048576
    ),
    result_id TEXT NOT NULL CHECK (
        length(result_id) = 64
        AND result_id NOT GLOB '*[^0-9a-f]*'
    ),
    result_body_digest TEXT NOT NULL CHECK (
        length(result_body_digest) = 64
        AND result_body_digest NOT GLOB '*[^0-9a-f]*'
    ),
    result_envelope_digest TEXT NOT NULL CHECK (
        length(result_envelope_digest) = 64
        AND result_envelope_digest NOT GLOB '*[^0-9a-f]*'
    ),
    result_signature_digest TEXT NOT NULL CHECK (
        length(result_signature_digest) = 64
        AND result_signature_digest NOT GLOB '*[^0-9a-f]*'
    ),
    result_json BLOB NOT NULL CHECK (
        typeof(result_json) = 'blob'
        AND length(result_json) BETWEEN 1 AND 1048576
    ),
    observed_head_sequence INTEGER NOT NULL CHECK (observed_head_sequence > 0),
    observed_head_digest TEXT NOT NULL CHECK (
        length(observed_head_digest) = 64
        AND observed_head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    resulting_head_sequence INTEGER NOT NULL CHECK (resulting_head_sequence > 0),
    resulting_head_digest TEXT NOT NULL CHECK (
        length(resulting_head_digest) = 64
        AND resulting_head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    participant_digest TEXT NOT NULL CHECK (
        length(participant_digest) = 64
        AND participant_digest NOT GLOB '*[^0-9a-f]*'
    ),
    participant_commit_sequence INTEGER NOT NULL UNIQUE CHECK (
        participant_commit_sequence > 0
    ),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    CHECK (
        (outcome = 'applied'
         AND resulting_head_sequence = observed_head_sequence + 1
         AND resulting_head_digest <> observed_head_digest)
        OR (outcome = 'not_applied'
            AND resulting_head_sequence = observed_head_sequence
            AND resulting_head_digest = observed_head_digest)
    ),
    FOREIGN KEY (operation_id)
        REFERENCES admission_operations(operation_id),
    FOREIGN KEY (obligation_id, obligation_atom_digest)
        REFERENCES obligation_atoms(obligation_id, atom_digest),
    FOREIGN KEY (obligation_id, observed_head_sequence, observed_head_digest)
        REFERENCES obligation_head_commits(obligation_id, head_sequence, head_digest),
    FOREIGN KEY (obligation_id, resulting_head_sequence, resulting_head_digest)
        REFERENCES obligation_head_commits(obligation_id, head_sequence, head_digest),
    FOREIGN KEY (participant_commit_sequence)
        REFERENCES admission_operation_commits(commit_sequence),
    FOREIGN KEY (authority_set_generation, authority_set_digest)
        REFERENCES factor_assignment_authority_sets(generation, active_set_digest),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch)
);

CREATE TRIGGER IF NOT EXISTS obligation_assignment_results_active_authority_set
BEFORE INSERT ON obligation_assignment_results
WHEN NOT EXISTS (
    SELECT 1 FROM factor_assignment_authority_sets AS authority_set
    WHERE authority_set.generation = NEW.authority_set_generation
      AND authority_set.active_set_digest = NEW.authority_set_digest
      AND authority_set.generation = (
          SELECT MAX(generation) FROM factor_assignment_authority_sets
      )
)
BEGIN
    SELECT RAISE(ABORT, 'obligation assignment result uses a stale authority set');
END;

CREATE TRIGGER IF NOT EXISTS obligation_assignment_results_exact_lease
BEFORE INSERT ON obligation_assignment_results
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'obligation assignment result has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS obligation_assignment_results_participant
BEFORE INSERT ON obligation_assignment_results
WHEN NOT EXISTS (
    SELECT 1 FROM admission_operation_commits AS committed
    WHERE committed.commit_sequence = NEW.participant_commit_sequence
      AND committed.operation_id = NEW.operation_id
      AND committed.mutation_kind = 'participant_update'
      AND committed.participant_digest = NEW.participant_digest
      AND committed.store_uuid = NEW.store_uuid
      AND committed.store_lease_id = NEW.store_lease_id
      AND committed.store_owner_epoch = NEW.store_owner_epoch
)
BEGIN
    SELECT RAISE(ABORT, 'obligation assignment result lacks its admission participant commit');
END;

CREATE TRIGGER IF NOT EXISTS obligation_assignment_results_head
BEFORE INSERT ON obligation_assignment_results
WHEN NOT EXISTS (
    SELECT 1
    FROM obligation_head_commits AS observed
    JOIN obligation_head_commits AS resulting
      ON resulting.obligation_id = observed.obligation_id
    JOIN obligation_heads AS current
      ON current.obligation_id = resulting.obligation_id
     AND current.head_sequence = resulting.head_sequence
     AND current.head_digest = resulting.head_digest
    WHERE observed.obligation_id = NEW.obligation_id
      AND observed.head_sequence = NEW.observed_head_sequence
      AND observed.head_digest = NEW.observed_head_digest
      AND observed.atom_digest = NEW.obligation_atom_digest
      AND resulting.head_sequence = NEW.resulting_head_sequence
      AND resulting.head_digest = NEW.resulting_head_digest
      AND resulting.atom_digest = NEW.obligation_atom_digest
      AND (
          (NEW.outcome = 'applied'
           AND resulting.previous_head_digest = observed.head_digest
           AND resulting.source_kind = 'disposition_transition'
           AND resulting.source_operation_id = NEW.operation_id
           AND resulting.participant_digest = NEW.participant_digest
           AND resulting.participant_commit_sequence = NEW.participant_commit_sequence)
          OR (NEW.outcome = 'not_applied'
              AND NOT EXISTS (
                  SELECT 1 FROM obligation_head_commits AS advanced
                  WHERE advanced.source_operation_id = NEW.operation_id
                    AND advanced.source_kind <> 'initial_projection'
              ))
      )
)
BEGIN
    SELECT RAISE(ABORT, 'obligation assignment result lacks its exact head state');
END;

CREATE TRIGGER IF NOT EXISTS obligation_assignment_results_immutable
BEFORE UPDATE ON obligation_assignment_results
BEGIN
    SELECT RAISE(ABORT, 'obligation assignment result is immutable');
END;

CREATE TRIGGER IF NOT EXISTS obligation_assignment_results_no_delete
BEFORE DELETE ON obligation_assignment_results
BEGIN
    SELECT RAISE(ABORT, 'obligation assignment result is immutable');
END;

CREATE TRIGGER IF NOT EXISTS obligation_assignment_results_fence_later_head
BEFORE INSERT ON obligation_head_commits
WHEN NEW.source_kind <> 'initial_projection'
 AND EXISTS (
    SELECT 1 FROM obligation_assignment_results AS result
    WHERE result.operation_id = NEW.source_operation_id
      AND result.outcome = 'not_applied'
)
BEGIN
    SELECT RAISE(ABORT, 'not-applied assignment operation cannot advance an obligation head');
END;

CREATE TABLE IF NOT EXISTS admission_operation_authorization_consumptions (
    operation_id TEXT NOT NULL PRIMARY KEY,
    authorization_receipt_id TEXT NOT NULL UNIQUE
        CHECK (length(authorization_receipt_id) BETWEEN 1 AND 512),
    consumer_receipt_id TEXT NOT NULL
        CHECK (length(consumer_receipt_id) BETWEEN 1 AND 512),
    request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 512),
    session_id TEXT NOT NULL CHECK (length(session_id) BETWEEN 1 AND 512),
    tool_call_id TEXT NOT NULL CHECK (length(tool_call_id) BETWEEN 1 AND 512),
    tenant_id TEXT CHECK (tenant_id IS NULL OR length(tenant_id) BETWEEN 1 AND 512),
    parameter_hash TEXT NOT NULL CHECK (
        length(parameter_hash) = 64
        AND parameter_hash NOT GLOB '*[^0-9a-f]*'
    ),
    consumed_at_unix_ms INTEGER NOT NULL CHECK (consumed_at_unix_ms > 0),
    record_digest TEXT NOT NULL CHECK (
        length(record_digest) = 64
        AND record_digest NOT GLOB '*[^0-9a-f]*'
    ),
    record_json BLOB NOT NULL CHECK (length(record_json) BETWEEN 1 AND 1048576),
    FOREIGN KEY (operation_id)
        REFERENCES admission_operation_terminal_projections(operation_id)
);

CREATE INDEX IF NOT EXISTS admission_operation_authorization_consumer
    ON admission_operation_authorization_consumptions(consumer_receipt_id);

CREATE TRIGGER IF NOT EXISTS admission_operation_authorization_consumptions_immutable
BEFORE UPDATE ON admission_operation_authorization_consumptions
BEGIN
    SELECT RAISE(ABORT, 'admission authorization consumption is immutable');
END;

CREATE TRIGGER IF NOT EXISTS admission_operation_authorization_consumptions_no_delete
BEFORE DELETE ON admission_operation_authorization_consumptions
BEGIN
    SELECT RAISE(ABORT, 'admission authorization consumption is immutable');
END;

CREATE TABLE IF NOT EXISTS admission_operation_observer_attempts (
    operation_id TEXT NOT NULL PRIMARY KEY,
    receipt_id TEXT NOT NULL UNIQUE CHECK (length(receipt_id) BETWEEN 1 AND 512),
    work_state TEXT NOT NULL CHECK (work_state IN (
        'pending', 'claimed', 'completed', 'failed'
    )),
    attempts INTEGER NOT NULL CHECK (attempts >= 0),
    next_visible_at_unix_ms INTEGER NOT NULL CHECK (next_visible_at_unix_ms > 0),
    row_version INTEGER NOT NULL CHECK (row_version >= 0),
    last_error TEXT CHECK (last_error IS NULL OR length(last_error) BETWEEN 1 AND 2048),
    record_digest TEXT NOT NULL CHECK (
        length(record_digest) = 64
        AND record_digest NOT GLOB '*[^0-9a-f]*'
    ),
    record_json BLOB NOT NULL CHECK (length(record_json) BETWEEN 1 AND 1048576),
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms > 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK (
        updated_at_unix_ms >= created_at_unix_ms
    ),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    FOREIGN KEY (operation_id)
        REFERENCES admission_operation_terminal_projections(operation_id),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch)
);

CREATE INDEX IF NOT EXISTS admission_operation_observer_attempts_ready
    ON admission_operation_observer_attempts(
        work_state, next_visible_at_unix_ms, operation_id
    );

CREATE TRIGGER IF NOT EXISTS admission_operation_observer_attempts_exact_lease_insert
BEFORE INSERT ON admission_operation_observer_attempts
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'admission observer attempt has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS admission_operation_observer_attempts_exact_lease_update
BEFORE UPDATE ON admission_operation_observer_attempts
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'admission observer attempt has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS admission_operation_observer_attempts_immutable_evidence
BEFORE UPDATE OF operation_id, receipt_id, record_digest, record_json, created_at_unix_ms
ON admission_operation_observer_attempts
BEGIN
    SELECT RAISE(ABORT, 'admission observer evidence is immutable');
END;

CREATE TRIGGER IF NOT EXISTS admission_operation_observer_attempts_versioned
BEFORE UPDATE ON admission_operation_observer_attempts
WHEN NEW.row_version <> OLD.row_version + 1
BEGIN
    SELECT RAISE(ABORT, 'admission observer attempt requires one version increment');
END;

CREATE TRIGGER IF NOT EXISTS admission_operation_observer_attempts_no_delete
BEFORE DELETE ON admission_operation_observer_attempts
BEGIN
    SELECT RAISE(ABORT, 'admission observer attempt must be retained');
END;

CREATE TABLE IF NOT EXISTS credit_exposure_accounts (
    debtor_id TEXT NOT NULL CHECK (length(debtor_id) BETWEEN 1 AND 512),
    scope_digest TEXT NOT NULL CHECK (
        length(scope_digest) = 64
        AND scope_digest = lower(scope_digest)
        AND scope_digest NOT GLOB '*[^0-9a-f]*'
    ),
    currency TEXT NOT NULL CHECK (length(currency) BETWEEN 1 AND 32),
    open_units INTEGER NOT NULL CHECK (open_units BETWEEN 0 AND 9007199254740991),
    reserved_units INTEGER NOT NULL CHECK (reserved_units BETWEEN 0 AND 9007199254740991),
    effective_ceiling_units INTEGER NOT NULL CHECK (
        effective_ceiling_units BETWEEN 1 AND 9007199254740991
    ),
    authority_configuration_digest TEXT NOT NULL CHECK (
        length(authority_configuration_digest) = 64
        AND authority_configuration_digest = lower(authority_configuration_digest)
        AND authority_configuration_digest NOT GLOB '*[^0-9a-f]*'
    ),
    authority_set_digest TEXT NOT NULL CHECK (
        length(authority_set_digest) = 64
        AND authority_set_digest = lower(authority_set_digest)
        AND authority_set_digest NOT GLOB '*[^0-9a-f]*'
    ),
    authority_evidence_digest TEXT NOT NULL CHECK (
        length(authority_evidence_digest) = 64
        AND authority_evidence_digest = lower(authority_evidence_digest)
        AND authority_evidence_digest NOT GLOB '*[^0-9a-f]*'
    ),
    authority_expires_at_unix_seconds INTEGER NOT NULL CHECK (
        authority_expires_at_unix_seconds BETWEEN 1 AND 9007199254740991
    ),
    account_version INTEGER NOT NULL CHECK (account_version BETWEEN 1 AND 9007199254740991),
    resource_fence INTEGER NOT NULL CHECK (resource_fence BETWEEN 1 AND 9007199254740991),
    updated_at_unix_ms INTEGER NOT NULL CHECK (
        updated_at_unix_ms BETWEEN 1 AND 9007199254740991
    ),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    PRIMARY KEY (debtor_id, scope_digest, currency),
    CHECK (open_units <= effective_ceiling_units - reserved_units),
    CHECK (account_version = resource_fence),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch)
);

CREATE TRIGGER IF NOT EXISTS credit_exposure_accounts_exact_lease_insert
BEFORE INSERT ON credit_exposure_accounts
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'credit exposure account has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS credit_exposure_accounts_exact_lease_update
BEFORE UPDATE ON credit_exposure_accounts
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'credit exposure account has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS credit_exposure_accounts_versioned
BEFORE UPDATE ON credit_exposure_accounts
WHEN NEW.debtor_id <> OLD.debtor_id
  OR NEW.scope_digest <> OLD.scope_digest
  OR NEW.currency <> OLD.currency
  OR NEW.store_uuid <> OLD.store_uuid
  OR NEW.account_version <> OLD.account_version + 1
  OR NEW.resource_fence <> OLD.resource_fence + 1
  OR NEW.account_version <> NEW.resource_fence
  OR NEW.updated_at_unix_ms < OLD.updated_at_unix_ms
BEGIN
    SELECT RAISE(ABORT, 'credit exposure account update is not a fenced successor');
END;

CREATE TRIGGER IF NOT EXISTS credit_exposure_accounts_no_delete
BEFORE DELETE ON credit_exposure_accounts
BEGIN
    SELECT RAISE(ABORT, 'credit exposure account must be retained');
END;

CREATE TABLE IF NOT EXISTS credit_exposure_reservations (
    operation_id TEXT NOT NULL PRIMARY KEY,
    reservation_digest TEXT NOT NULL UNIQUE CHECK (
        length(reservation_digest) = 64
        AND reservation_digest = lower(reservation_digest)
        AND reservation_digest NOT GLOB '*[^0-9a-f]*'
    ),
    debtor_id TEXT NOT NULL,
    scope_digest TEXT NOT NULL,
    currency TEXT NOT NULL,
    action_nonce TEXT NOT NULL CHECK (length(action_nonce) BETWEEN 1 AND 512),
    amount_units INTEGER NOT NULL CHECK (amount_units BETWEEN 1 AND 9007199254740991),
    source_account_version INTEGER NOT NULL CHECK (
        source_account_version BETWEEN 1 AND 9007199254740991
    ),
    source_resource_fence INTEGER NOT NULL CHECK (
        source_resource_fence BETWEEN 1 AND 9007199254740991
    ),
    reserved_account_version INTEGER NOT NULL CHECK (
        reserved_account_version BETWEEN 1 AND 9007199254740991
    ),
    reserved_resource_fence INTEGER NOT NULL CHECK (
        reserved_resource_fence BETWEEN 1 AND 9007199254740991
    ),
    reservation_json BLOB NOT NULL CHECK (length(reservation_json) > 0),
    reserved_at_unix_ms INTEGER NOT NULL CHECK (
        reserved_at_unix_ms BETWEEN 1 AND 9007199254740991
    ),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    UNIQUE (debtor_id, scope_digest, currency, action_nonce),
    UNIQUE (operation_id, reservation_digest),
    CHECK (source_account_version = source_resource_fence),
    CHECK (reserved_account_version = reserved_resource_fence),
    CHECK (reserved_account_version = source_account_version + 1),
    FOREIGN KEY (operation_id) REFERENCES admission_operations(operation_id),
    FOREIGN KEY (debtor_id, scope_digest, currency)
        REFERENCES credit_exposure_accounts(debtor_id, scope_digest, currency),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch)
);

CREATE TRIGGER IF NOT EXISTS credit_exposure_reservations_exact_lease
BEFORE INSERT ON credit_exposure_reservations
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'credit exposure reservation has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS credit_exposure_reservations_source_account
BEFORE INSERT ON credit_exposure_reservations
WHEN NOT EXISTS (
    SELECT 1 FROM credit_exposure_accounts
    WHERE debtor_id = NEW.debtor_id
      AND scope_digest = NEW.scope_digest
      AND currency = NEW.currency
      AND account_version = NEW.source_account_version
      AND resource_fence = NEW.source_resource_fence
)
BEGIN
    SELECT RAISE(ABORT, 'credit exposure reservation source account is stale');
END;

CREATE TRIGGER IF NOT EXISTS credit_exposure_reservations_immutable
BEFORE UPDATE ON credit_exposure_reservations
BEGIN
    SELECT RAISE(ABORT, 'credit exposure reservation is immutable');
END;

CREATE TRIGGER IF NOT EXISTS credit_exposure_reservations_no_delete
BEFORE DELETE ON credit_exposure_reservations
BEGIN
    SELECT RAISE(ABORT, 'credit exposure reservation must be retained');
END;

CREATE TABLE IF NOT EXISTS credit_exposure_terminal_transitions (
    operation_id TEXT NOT NULL PRIMARY KEY,
    reservation_digest TEXT NOT NULL,
    terminal_state TEXT NOT NULL CHECK (
        terminal_state IN ('committed', 'released_before_dispatch', 'outcome_unknown')
    ),
    admission_terminal_state TEXT NOT NULL CHECK (
        admission_terminal_state IN (
            'completed', 'compensated_before_dispatch',
            'not_accepted_after_dispatch_commit', 'outcome_unknown_after_dispatch'
        )
    ),
    projection_digest TEXT NOT NULL CHECK (
        length(projection_digest) = 64
        AND projection_digest = lower(projection_digest)
        AND projection_digest NOT GLOB '*[^0-9a-f]*'
    ),
    obligation_id TEXT,
    account_version INTEGER NOT NULL CHECK (account_version BETWEEN 1 AND 9007199254740991),
    resource_fence INTEGER NOT NULL CHECK (resource_fence BETWEEN 1 AND 9007199254740991),
    transition_json BLOB NOT NULL CHECK (length(transition_json) > 0),
    transitioned_at_unix_ms INTEGER NOT NULL CHECK (
        transitioned_at_unix_ms BETWEEN 1 AND 9007199254740991
    ),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    CHECK ((terminal_state = 'committed') = (obligation_id IS NOT NULL)),
    CHECK (account_version = resource_fence),
    FOREIGN KEY (operation_id, reservation_digest)
        REFERENCES credit_exposure_reservations(operation_id, reservation_digest),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch)
);

CREATE TRIGGER IF NOT EXISTS credit_exposure_terminal_transitions_exact_lease
BEFORE INSERT ON credit_exposure_terminal_transitions
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'credit exposure terminal transition has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS credit_exposure_terminal_transitions_legal
BEFORE INSERT ON credit_exposure_terminal_transitions
WHEN NOT EXISTS (
    SELECT 1
    FROM credit_exposure_reservations AS reserved
    JOIN credit_exposure_accounts AS account
      ON account.debtor_id = reserved.debtor_id
     AND account.scope_digest = reserved.scope_digest
     AND account.currency = reserved.currency
    JOIN admission_operation_terminal_projections AS projection
      ON projection.operation_id = reserved.operation_id
    WHERE reserved.operation_id = NEW.operation_id
      AND reserved.reservation_digest = NEW.reservation_digest
      AND account.account_version + 1 = NEW.account_version
      AND account.resource_fence + 1 = NEW.resource_fence
      AND projection.terminal_state = NEW.admission_terminal_state
      AND projection.projection_digest = NEW.projection_digest
      AND projection.store_uuid = NEW.store_uuid
      AND projection.store_lease_id = NEW.store_lease_id
      AND projection.store_owner_epoch = NEW.store_owner_epoch
      AND (
          (NEW.terminal_state = 'committed'
           AND NEW.admission_terminal_state = 'completed'
           AND EXISTS (
               SELECT 1 FROM obligation_atoms AS atom
               WHERE atom.operation_id = NEW.operation_id
                 AND atom.obligation_id = NEW.obligation_id
           ))
          OR (NEW.terminal_state = 'released_before_dispatch'
              AND NEW.admission_terminal_state = 'compensated_before_dispatch')
          OR (NEW.terminal_state = 'outcome_unknown'
              AND NEW.admission_terminal_state IN (
                  'not_accepted_after_dispatch_commit',
                  'outcome_unknown_after_dispatch'
              ))
      )
)
BEGIN
    SELECT RAISE(ABORT, 'credit exposure terminal transition is not legal');
END;

CREATE TRIGGER IF NOT EXISTS credit_exposure_terminal_transitions_immutable
BEFORE UPDATE ON credit_exposure_terminal_transitions
BEGIN
    SELECT RAISE(ABORT, 'credit exposure terminal transition is immutable');
END;

CREATE TRIGGER IF NOT EXISTS credit_exposure_terminal_transitions_no_delete
BEFORE DELETE ON credit_exposure_terminal_transitions
BEGIN
    SELECT RAISE(ABORT, 'credit exposure terminal transition must be retained');
END;
