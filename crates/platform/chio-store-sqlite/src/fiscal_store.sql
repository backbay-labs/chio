CREATE TABLE IF NOT EXISTS fiscal_authority_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    state_json BLOB NOT NULL CHECK (length(state_json) BETWEEN 1 AND 4194304),
    finalized_checkpoint_digest TEXT NOT NULL CHECK (
        length(finalized_checkpoint_digest) = 64
        AND finalized_checkpoint_digest NOT GLOB '*[^0-9a-f]*'
    ),
    state_version INTEGER NOT NULL CHECK (state_version > 0)
);

CREATE TABLE IF NOT EXISTS fiscal_genesis_policies (
    policy_id TEXT PRIMARY KEY CHECK (
        length(policy_id) = 64 AND policy_id NOT GLOB '*[^0-9a-f]*'
    ),
    policy_digest TEXT NOT NULL UNIQUE CHECK (
        length(policy_digest) = 64 AND policy_digest NOT GLOB '*[^0-9a-f]*'
    ),
    policy_json BLOB NOT NULL CHECK (length(policy_json) BETWEEN 1 AND 4194304)
);

CREATE TABLE IF NOT EXISTS fiscal_charters (
    charter_id TEXT PRIMARY KEY CHECK (
        length(charter_id) = 64 AND charter_id NOT GLOB '*[^0-9a-f]*'
    ),
    charter_digest TEXT NOT NULL UNIQUE CHECK (
        length(charter_digest) = 64 AND charter_digest NOT GLOB '*[^0-9a-f]*'
    ),
    charter_sequence INTEGER NOT NULL CHECK (charter_sequence > 0),
    lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN ('proposed', 'pinned', 'active', 'superseded')),
    signed_json BLOB NOT NULL CHECK (length(signed_json) BETWEEN 1 AND 4194304)
);

CREATE TABLE IF NOT EXISTS fiscal_schedules (
    schedule_id TEXT PRIMARY KEY CHECK (
        length(schedule_id) = 64 AND schedule_id NOT GLOB '*[^0-9a-f]*'
    ),
    schedule_digest TEXT NOT NULL UNIQUE CHECK (
        length(schedule_digest) = 64 AND schedule_digest NOT GLOB '*[^0-9a-f]*'
    ),
    domain_json TEXT NOT NULL CHECK (domain_json <> ''),
    schedule_sequence INTEGER NOT NULL CHECK (schedule_sequence > 0),
    lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN ('staged', 'active', 'superseded')),
    signed_json BLOB NOT NULL CHECK (length(signed_json) BETWEEN 1 AND 4194304)
);

CREATE TABLE IF NOT EXISTS fiscal_proposals (
    proposal_id TEXT PRIMARY KEY CHECK (
        length(proposal_id) = 64 AND proposal_id NOT GLOB '*[^0-9a-f]*'
    ),
    proposal_digest TEXT NOT NULL UNIQUE CHECK (
        length(proposal_digest) = 64 AND proposal_digest NOT GLOB '*[^0-9a-f]*'
    ),
    signed_json BLOB NOT NULL CHECK (length(signed_json) BETWEEN 1 AND 4194304)
);

CREATE TABLE IF NOT EXISTS fiscal_proposal_admissions (
    admission_id TEXT PRIMARY KEY CHECK (
        length(admission_id) = 64 AND admission_id NOT GLOB '*[^0-9a-f]*'
    ),
    admission_digest TEXT NOT NULL UNIQUE CHECK (
        length(admission_digest) = 64 AND admission_digest NOT GLOB '*[^0-9a-f]*'
    ),
    admitted_at INTEGER NOT NULL CHECK (admitted_at > 0),
    status TEXT NOT NULL CHECK (status IN ('admitted', 'activated')),
    state_version INTEGER NOT NULL CHECK (state_version > 0),
    state_json BLOB NOT NULL CHECK (length(state_json) BETWEEN 1 AND 4194304)
);

CREATE TABLE IF NOT EXISTS fiscal_admission_sequence (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    current_sequence INTEGER NOT NULL CHECK (current_sequence >= 0)
);

INSERT OR IGNORE INTO fiscal_admission_sequence (singleton, current_sequence)
SELECT 1, COALESCE(MAX(CAST(json_extract(state_json, '$.signedAdmission.body.admissionSequence') AS INTEGER)), 0)
FROM fiscal_proposal_admissions;

CREATE TABLE IF NOT EXISTS fiscal_approvals (
    approval_id TEXT PRIMARY KEY CHECK (
        length(approval_id) = 64 AND approval_id NOT GLOB '*[^0-9a-f]*'
    ),
    approval_digest TEXT NOT NULL UNIQUE CHECK (
        length(approval_digest) = 64 AND approval_digest NOT GLOB '*[^0-9a-f]*'
    ),
    signed_json BLOB NOT NULL CHECK (length(signed_json) BETWEEN 1 AND 4194304)
);

CREATE TABLE IF NOT EXISTS fiscal_activations (
    activation_id TEXT PRIMARY KEY CHECK (
        length(activation_id) = 64 AND activation_id NOT GLOB '*[^0-9a-f]*'
    ),
    activation_digest TEXT NOT NULL UNIQUE CHECK (
        length(activation_digest) = 64 AND activation_digest NOT GLOB '*[^0-9a-f]*'
    ),
    signed_json BLOB NOT NULL CHECK (length(signed_json) BETWEEN 1 AND 4194304)
);

CREATE TABLE IF NOT EXISTS fiscal_runtime_readiness (
    readiness_id TEXT PRIMARY KEY CHECK (
        length(readiness_id) = 64 AND readiness_id NOT GLOB '*[^0-9a-f]*'
    ),
    readiness_digest TEXT NOT NULL UNIQUE CHECK (
        length(readiness_digest) = 64 AND readiness_digest NOT GLOB '*[^0-9a-f]*'
    ),
    readiness_sequence INTEGER NOT NULL UNIQUE CHECK (readiness_sequence > 0),
    registry_json BLOB NOT NULL CHECK (length(registry_json) BETWEEN 1 AND 4194304),
    signed_json BLOB NOT NULL CHECK (length(signed_json) BETWEEN 1 AND 4194304)
);

CREATE TABLE IF NOT EXISTS fiscal_legacy_fee_schedule_bindings (
    legacy_schedule_id TEXT PRIMARY KEY CHECK (legacy_schedule_id <> ''),
    fiscal_schedule_id TEXT NOT NULL UNIQUE,
    fiscal_schedule_digest TEXT NOT NULL CHECK (
        length(fiscal_schedule_digest) = 64
        AND fiscal_schedule_digest NOT GLOB '*[^0-9a-f]*'
    ),
    legacy_envelope_digest TEXT NOT NULL CHECK (
        length(legacy_envelope_digest) = 64
        AND legacy_envelope_digest NOT GLOB '*[^0-9a-f]*'
    ),
    FOREIGN KEY (fiscal_schedule_id) REFERENCES fiscal_schedules(schedule_id)
);

CREATE TABLE IF NOT EXISTS fiscal_continuity_checkpoints (
    checkpoint_digest TEXT PRIMARY KEY CHECK (
        length(checkpoint_digest) = 64 AND checkpoint_digest NOT GLOB '*[^0-9a-f]*'
    ),
    continuity_sequence INTEGER NOT NULL UNIQUE CHECK (continuity_sequence >= 0),
    status TEXT NOT NULL CHECK (status IN ('finalized', 'staged')),
    signed_json BLOB NOT NULL CHECK (length(signed_json) BETWEEN 1 AND 4194304)
);

CREATE TABLE IF NOT EXISTS fiscal_staged_transitions (
    transition_id TEXT PRIMARY KEY CHECK (
        length(transition_id) = 64 AND transition_id NOT GLOB '*[^0-9a-f]*'
    ),
    current_checkpoint_digest TEXT NOT NULL,
    next_checkpoint_digest TEXT NOT NULL UNIQUE,
    proof_json BLOB NOT NULL CHECK (length(proof_json) BETWEEN 1 AND 4194304),
    status TEXT NOT NULL CHECK (status IN (
        'db_staged', 'fiscal_anchor_advanced', 'db_finalized', 'discarded'
    )),
    stage_version INTEGER NOT NULL CHECK (stage_version > 0),
    FOREIGN KEY (current_checkpoint_digest)
        REFERENCES fiscal_continuity_checkpoints(checkpoint_digest),
    FOREIGN KEY (next_checkpoint_digest)
        REFERENCES fiscal_continuity_checkpoints(checkpoint_digest)
);

CREATE TABLE IF NOT EXISTS fiscal_staged_activation_mutations (
    transition_id TEXT PRIMARY KEY,
    activation_id TEXT NOT NULL UNIQUE,
    activation_digest TEXT NOT NULL UNIQUE CHECK (
        length(activation_digest) = 64 AND activation_digest NOT GLOB '*[^0-9a-f]*'
    ),
    admission_id TEXT NOT NULL UNIQUE,
    admission_digest TEXT NOT NULL CHECK (
        length(admission_digest) = 64 AND admission_digest NOT GLOB '*[^0-9a-f]*'
    ),
    expected_admission_version INTEGER NOT NULL CHECK (expected_admission_version > 0),
    activated_admission_version INTEGER NOT NULL CHECK (
        activated_admission_version = expected_admission_version + 1
    ),
    activated_admission_json BLOB NOT NULL CHECK (
        length(activated_admission_json) BETWEEN 1 AND 4194304
    ),
    candidate_schedule_id TEXT NOT NULL UNIQUE,
    candidate_schedule_digest TEXT NOT NULL CHECK (
        length(candidate_schedule_digest) = 64
        AND candidate_schedule_digest NOT GLOB '*[^0-9a-f]*'
    ),
    predecessor_schedule_id TEXT,
    predecessor_schedule_digest TEXT CHECK (
        predecessor_schedule_digest IS NULL OR (
            length(predecessor_schedule_digest) = 64
            AND predecessor_schedule_digest NOT GLOB '*[^0-9a-f]*'
        )
    ),
    CHECK ((predecessor_schedule_id IS NULL) = (predecessor_schedule_digest IS NULL)),
    FOREIGN KEY (transition_id) REFERENCES fiscal_staged_transitions(transition_id),
    FOREIGN KEY (activation_id) REFERENCES fiscal_activations(activation_id),
    FOREIGN KEY (admission_id) REFERENCES fiscal_proposal_admissions(admission_id),
    FOREIGN KEY (candidate_schedule_id) REFERENCES fiscal_schedules(schedule_id),
    FOREIGN KEY (predecessor_schedule_id) REFERENCES fiscal_schedules(schedule_id)
);

CREATE TABLE IF NOT EXISTS fiscal_staged_rotation_mutations (
    transition_id TEXT PRIMARY KEY,
    activation_id TEXT NOT NULL UNIQUE,
    activation_digest TEXT NOT NULL UNIQUE CHECK (
        length(activation_digest) = 64 AND activation_digest NOT GLOB '*[^0-9a-f]*'
    ),
    admission_id TEXT NOT NULL UNIQUE,
    admission_digest TEXT NOT NULL CHECK (
        length(admission_digest) = 64 AND admission_digest NOT GLOB '*[^0-9a-f]*'
    ),
    expected_admission_version INTEGER NOT NULL CHECK (expected_admission_version > 0),
    activated_admission_version INTEGER NOT NULL CHECK (
        activated_admission_version = expected_admission_version + 1
    ),
    activated_admission_json BLOB NOT NULL CHECK (
        length(activated_admission_json) BETWEEN 1 AND 4194304
    ),
    successor_charter_id TEXT NOT NULL UNIQUE,
    successor_charter_digest TEXT NOT NULL UNIQUE CHECK (
        length(successor_charter_digest) = 64
        AND successor_charter_digest NOT GLOB '*[^0-9a-f]*'
    ),
    predecessor_charter_id TEXT NOT NULL UNIQUE,
    predecessor_charter_digest TEXT NOT NULL UNIQUE CHECK (
        length(predecessor_charter_digest) = 64
        AND predecessor_charter_digest NOT GLOB '*[^0-9a-f]*'
    ),
    FOREIGN KEY (transition_id) REFERENCES fiscal_staged_transitions(transition_id),
    FOREIGN KEY (activation_id) REFERENCES fiscal_activations(activation_id),
    FOREIGN KEY (admission_id) REFERENCES fiscal_proposal_admissions(admission_id),
    FOREIGN KEY (successor_charter_id) REFERENCES fiscal_charters(charter_id),
    FOREIGN KEY (predecessor_charter_id) REFERENCES fiscal_charters(charter_id)
);

CREATE TABLE IF NOT EXISTS fiscal_staged_rotation_schedules (
    transition_id TEXT NOT NULL,
    domain_json TEXT NOT NULL CHECK (domain_json <> ''),
    candidate_schedule_id TEXT NOT NULL UNIQUE,
    candidate_schedule_digest TEXT NOT NULL UNIQUE CHECK (
        length(candidate_schedule_digest) = 64
        AND candidate_schedule_digest NOT GLOB '*[^0-9a-f]*'
    ),
    predecessor_schedule_id TEXT NOT NULL UNIQUE,
    predecessor_schedule_digest TEXT NOT NULL UNIQUE CHECK (
        length(predecessor_schedule_digest) = 64
        AND predecessor_schedule_digest NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (transition_id, domain_json),
    FOREIGN KEY (transition_id) REFERENCES fiscal_staged_rotation_mutations(transition_id),
    FOREIGN KEY (candidate_schedule_id) REFERENCES fiscal_schedules(schedule_id),
    FOREIGN KEY (predecessor_schedule_id) REFERENCES fiscal_schedules(schedule_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS fiscal_one_open_transition
ON fiscal_staged_transitions((1))
WHERE status IN ('db_staged', 'fiscal_anchor_advanced');

CREATE TABLE IF NOT EXISTS fiscal_projection_commits (
    projection_key TEXT NOT NULL CHECK (projection_key <> ''),
    projection_sequence INTEGER NOT NULL CHECK (projection_sequence > 0),
    mutation_kind TEXT NOT NULL CHECK (mutation_kind <> ''),
    snapshot_digest TEXT NOT NULL CHECK (
        length(snapshot_digest) = 64 AND snapshot_digest NOT GLOB '*[^0-9a-f]*'
    ),
    previous_commit_digest TEXT NOT NULL CHECK (
        length(previous_commit_digest) = 64
        AND previous_commit_digest NOT GLOB '*[^0-9a-f]*'
    ),
    commit_digest TEXT NOT NULL UNIQUE CHECK (
        length(commit_digest) = 64 AND commit_digest NOT GLOB '*[^0-9a-f]*'
    ),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    PRIMARY KEY (projection_key, projection_sequence),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch)
);

CREATE TRIGGER IF NOT EXISTS fiscal_signed_artifacts_immutable
BEFORE UPDATE OF charter_id, charter_digest, charter_sequence, signed_json
ON fiscal_charters
BEGIN SELECT RAISE(ABORT, 'signed fiscal charter is immutable'); END;
CREATE TRIGGER IF NOT EXISTS fiscal_signed_schedules_immutable
BEFORE UPDATE OF schedule_id, schedule_digest, domain_json, schedule_sequence, signed_json
ON fiscal_schedules
BEGIN SELECT RAISE(ABORT, 'signed fiscal schedule is immutable'); END;
CREATE TRIGGER IF NOT EXISTS fiscal_signed_proposals_immutable
BEFORE UPDATE ON fiscal_proposals
BEGIN SELECT RAISE(ABORT, 'signed fiscal proposal is immutable'); END;
CREATE TRIGGER IF NOT EXISTS fiscal_signed_approvals_immutable
BEFORE UPDATE ON fiscal_approvals
BEGIN SELECT RAISE(ABORT, 'signed fiscal approval is immutable'); END;
CREATE TRIGGER IF NOT EXISTS fiscal_signed_activations_immutable
BEFORE UPDATE ON fiscal_activations
BEGIN SELECT RAISE(ABORT, 'signed fiscal activation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS fiscal_legacy_fee_schedule_bindings_immutable
BEFORE UPDATE ON fiscal_legacy_fee_schedule_bindings
BEGIN SELECT RAISE(ABORT, 'fiscal legacy fee schedule binding is immutable'); END;
CREATE TRIGGER IF NOT EXISTS fiscal_legacy_fee_schedule_bindings_no_delete
BEFORE DELETE ON fiscal_legacy_fee_schedule_bindings
BEGIN SELECT RAISE(ABORT, 'fiscal legacy fee schedule binding is immutable'); END;
CREATE TRIGGER IF NOT EXISTS fiscal_staged_activation_mutations_immutable
BEFORE UPDATE ON fiscal_staged_activation_mutations
BEGIN SELECT RAISE(ABORT, 'fiscal staged activation mutation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS fiscal_staged_activation_mutations_no_delete
BEFORE DELETE ON fiscal_staged_activation_mutations
BEGIN SELECT RAISE(ABORT, 'fiscal staged activation mutation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS fiscal_staged_rotation_mutations_immutable
BEFORE UPDATE ON fiscal_staged_rotation_mutations
BEGIN SELECT RAISE(ABORT, 'fiscal staged rotation mutation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS fiscal_staged_rotation_mutations_no_delete
BEFORE DELETE ON fiscal_staged_rotation_mutations
BEGIN SELECT RAISE(ABORT, 'fiscal staged rotation mutation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS fiscal_staged_rotation_schedules_immutable
BEFORE UPDATE ON fiscal_staged_rotation_schedules
BEGIN SELECT RAISE(ABORT, 'fiscal staged rotation schedules are immutable'); END;
CREATE TRIGGER IF NOT EXISTS fiscal_staged_rotation_schedules_no_delete
BEFORE DELETE ON fiscal_staged_rotation_schedules
BEGIN SELECT RAISE(ABORT, 'fiscal staged rotation schedules are immutable'); END;
CREATE TRIGGER IF NOT EXISTS fiscal_checkpoints_immutable
BEFORE UPDATE OF checkpoint_digest, continuity_sequence, signed_json
ON fiscal_continuity_checkpoints
BEGIN SELECT RAISE(ABORT, 'signed fiscal checkpoint is immutable'); END;
CREATE TRIGGER IF NOT EXISTS fiscal_projection_commits_immutable
BEFORE UPDATE ON fiscal_projection_commits
BEGIN SELECT RAISE(ABORT, 'fiscal projection commit is immutable'); END;
CREATE TRIGGER IF NOT EXISTS fiscal_projection_commits_no_delete
BEFORE DELETE ON fiscal_projection_commits
BEGIN SELECT RAISE(ABORT, 'fiscal projection commit is immutable'); END;
