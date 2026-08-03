CREATE TABLE IF NOT EXISTS finding_status_feeds (
    feed_id TEXT NOT NULL PRIMARY KEY
        CHECK (length(feed_id) BETWEEN 1 AND 512),
    operator_id TEXT NOT NULL
        CHECK (length(operator_id) BETWEEN 1 AND 512),
    key_domain_nonce INTEGER NOT NULL
        CHECK (key_domain_nonce = 3318287169837494),
    registered_at INTEGER NOT NULL CHECK (registered_at > 0),
    UNIQUE (feed_id, operator_id)
);

CREATE TRIGGER IF NOT EXISTS finding_status_feeds_immutable
BEFORE UPDATE ON finding_status_feeds
BEGIN
    SELECT RAISE(ABORT, 'finding status feed identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS finding_status_feeds_no_delete
BEFORE DELETE ON finding_status_feeds
BEGIN
    SELECT RAISE(ABORT, 'finding status feed identity must be retained');
END;

CREATE TABLE IF NOT EXISTS finding_status_epochs (
    feed_id TEXT NOT NULL,
    operator_id TEXT NOT NULL,
    key_domain_nonce INTEGER NOT NULL
        CHECK (key_domain_nonce = 3318287169837494),
    map_epoch INTEGER NOT NULL CHECK (map_epoch > 0),
    epoch_id TEXT NOT NULL
        CHECK (length(epoch_id) = 64 AND epoch_id NOT GLOB '*[^0-9a-f]*'),
    root_hash TEXT NOT NULL
        CHECK (length(root_hash) = 64 AND root_hash NOT GLOB '*[^0-9a-f]*'),
    signed_epoch_sha256 TEXT NOT NULL CHECK (
        length(signed_epoch_sha256) = 64
        AND signed_epoch_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    signed_epoch_bytes BLOB NOT NULL CHECK (
        typeof(signed_epoch_bytes) = 'blob'
        AND length(signed_epoch_bytes) BETWEEN 1 AND 262144
    ),
    operator_key TEXT NOT NULL
        CHECK (length(operator_key) BETWEEN 1 AND 4096),
    operator_key_epoch INTEGER NOT NULL CHECK (operator_key_epoch >= 0),
    operator_authorization_sha256 TEXT NOT NULL CHECK (
        length(operator_authorization_sha256) = 64
        AND operator_authorization_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    generated_at INTEGER NOT NULL CHECK (generated_at > 0),
    valid_until INTEGER NOT NULL CHECK (valid_until > generated_at),
    recorded_at INTEGER NOT NULL CHECK (recorded_at >= generated_at),
    PRIMARY KEY (feed_id, map_epoch),
    UNIQUE (feed_id, epoch_id),
    FOREIGN KEY (feed_id, operator_id)
        REFERENCES finding_status_feeds(feed_id, operator_id)
);

CREATE INDEX IF NOT EXISTS finding_status_epochs_by_operator
    ON finding_status_epochs(operator_id, feed_id, map_epoch);

CREATE TRIGGER IF NOT EXISTS finding_status_epochs_immutable
BEFORE UPDATE ON finding_status_epochs
BEGIN
    SELECT RAISE(ABORT, 'finding status epoch is immutable');
END;

CREATE TRIGGER IF NOT EXISTS finding_status_epochs_no_delete
BEFORE DELETE ON finding_status_epochs
BEGIN
    SELECT RAISE(ABORT, 'finding status epochs must be retained');
END;

CREATE TABLE IF NOT EXISTS finding_status_feed_floors (
    feed_id TEXT NOT NULL PRIMARY KEY,
    operator_id TEXT NOT NULL,
    key_domain_nonce INTEGER NOT NULL
        CHECK (key_domain_nonce = 3318287169837494),
    map_epoch INTEGER NOT NULL CHECK (map_epoch > 0),
    epoch_id TEXT NOT NULL
        CHECK (length(epoch_id) = 64 AND epoch_id NOT GLOB '*[^0-9a-f]*'),
    root_hash TEXT NOT NULL
        CHECK (length(root_hash) = 64 AND root_hash NOT GLOB '*[^0-9a-f]*'),
    signed_epoch_sha256 TEXT NOT NULL CHECK (
        length(signed_epoch_sha256) = 64
        AND signed_epoch_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    operator_key TEXT NOT NULL
        CHECK (length(operator_key) BETWEEN 1 AND 4096),
    operator_key_epoch INTEGER NOT NULL CHECK (operator_key_epoch >= 0),
    operator_authorization_sha256 TEXT NOT NULL CHECK (
        length(operator_authorization_sha256) = 64
        AND operator_authorization_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    advanced_at INTEGER NOT NULL CHECK (advanced_at > 0),
    FOREIGN KEY (feed_id, operator_id)
        REFERENCES finding_status_feeds(feed_id, operator_id),
    FOREIGN KEY (feed_id, map_epoch)
        REFERENCES finding_status_epochs(feed_id, map_epoch)
);

CREATE TRIGGER IF NOT EXISTS finding_status_feed_floors_monotonic
BEFORE UPDATE ON finding_status_feed_floors
WHEN NEW.feed_id <> OLD.feed_id
  OR NEW.operator_id <> OLD.operator_id
  OR NEW.key_domain_nonce <> OLD.key_domain_nonce
  OR NEW.map_epoch <= OLD.map_epoch
  OR NEW.operator_key_epoch < OLD.operator_key_epoch
  OR (
      NEW.operator_key_epoch = OLD.operator_key_epoch
      AND (
          NEW.operator_key <> OLD.operator_key
          OR NEW.operator_authorization_sha256
              <> OLD.operator_authorization_sha256
      )
  )
BEGIN
    SELECT RAISE(ABORT, 'finding status floor must advance monotonically');
END;

CREATE TRIGGER IF NOT EXISTS finding_status_feed_floors_no_delete
BEFORE DELETE ON finding_status_feed_floors
BEGIN
    SELECT RAISE(ABORT, 'finding status floor must be retained');
END;

CREATE TABLE IF NOT EXISTS finding_retraction_intents (
    intent_id TEXT NOT NULL PRIMARY KEY
        CHECK (length(intent_id) = 64 AND intent_id NOT GLOB '*[^0-9a-f]*'),
    feed_id TEXT NOT NULL,
    operator_id TEXT NOT NULL,
    finding_id TEXT NOT NULL
        CHECK (length(finding_id) = 64 AND finding_id NOT GLOB '*[^0-9a-f]*'),
    source TEXT NOT NULL CHECK (source IN ('voluntary', 'enforcement')),
    intent_sha256 TEXT NOT NULL CHECK (
        length(intent_sha256) = 64
        AND intent_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    intent_bytes BLOB NOT NULL CHECK (
        typeof(intent_bytes) = 'blob'
        AND length(intent_bytes) BETWEEN 1 AND 262144
    ),
    issued_at INTEGER NOT NULL CHECK (issued_at > 0),
    inclusion_deadline INTEGER NOT NULL CHECK (inclusion_deadline > issued_at),
    state TEXT NOT NULL CHECK (
        state IN ('waiting_finality', 'dispatch_eligible', 'published')
    ),
    finality_evidence_sha256 TEXT CHECK (
        finality_evidence_sha256 IS NULL
        OR (
            length(finality_evidence_sha256) = 64
            AND finality_evidence_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    finality_evidence_bytes BLOB CHECK (
        finality_evidence_bytes IS NULL
        OR (
            typeof(finality_evidence_bytes) = 'blob'
            AND length(finality_evidence_bytes) BETWEEN 1 AND 262144
        )
    ),
    dispatch_eligible_at INTEGER,
    published_map_epoch INTEGER,
    published_epoch_id TEXT CHECK (
        published_epoch_id IS NULL
        OR (
            length(published_epoch_id) = 64
            AND published_epoch_id NOT GLOB '*[^0-9a-f]*'
        )
    ),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    UNIQUE (feed_id, finding_id),
    FOREIGN KEY (feed_id, operator_id)
        REFERENCES finding_status_feeds(feed_id, operator_id),
    FOREIGN KEY (feed_id, published_map_epoch)
        REFERENCES finding_status_epochs(feed_id, map_epoch),
    CHECK (
        (state = 'waiting_finality'
            AND finality_evidence_sha256 IS NULL
            AND finality_evidence_bytes IS NULL
            AND dispatch_eligible_at IS NULL
            AND published_map_epoch IS NULL
            AND published_epoch_id IS NULL)
        OR
        (state = 'dispatch_eligible'
            AND finality_evidence_sha256 IS NOT NULL
            AND finality_evidence_bytes IS NOT NULL
            AND dispatch_eligible_at IS NOT NULL
            AND published_map_epoch IS NULL
            AND published_epoch_id IS NULL)
        OR
        (state = 'published'
            AND finality_evidence_sha256 IS NOT NULL
            AND finality_evidence_bytes IS NOT NULL
            AND dispatch_eligible_at IS NOT NULL
            AND published_map_epoch IS NOT NULL
            AND published_epoch_id IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS finding_retraction_intents_outbox
    ON finding_retraction_intents(feed_id, state, created_at, intent_id);

CREATE TRIGGER IF NOT EXISTS finding_retraction_intents_lifecycle
BEFORE UPDATE ON finding_retraction_intents
WHEN NEW.intent_id <> OLD.intent_id
  OR NEW.feed_id <> OLD.feed_id
  OR NEW.operator_id <> OLD.operator_id
  OR NEW.finding_id <> OLD.finding_id
  OR NEW.source <> OLD.source
  OR NEW.intent_sha256 <> OLD.intent_sha256
  OR NEW.intent_bytes <> OLD.intent_bytes
  OR NEW.issued_at <> OLD.issued_at
  OR NEW.inclusion_deadline <> OLD.inclusion_deadline
  OR NEW.created_at <> OLD.created_at
  OR NOT (
      (OLD.state = 'waiting_finality' AND NEW.state = 'dispatch_eligible')
      OR (OLD.state = 'dispatch_eligible' AND NEW.state = 'published')
  )
BEGIN
    SELECT RAISE(ABORT, 'invalid finding retraction intent transition');
END;

CREATE TRIGGER IF NOT EXISTS finding_retraction_intents_no_delete
BEFORE DELETE ON finding_retraction_intents
BEGIN
    SELECT RAISE(ABORT, 'finding retraction intent must be retained');
END;

CREATE TABLE IF NOT EXISTS finding_status_states (
    feed_id TEXT NOT NULL,
    operator_id TEXT NOT NULL,
    finding_id TEXT NOT NULL
        CHECK (length(finding_id) = 64 AND finding_id NOT GLOB '*[^0-9a-f]*'),
    state TEXT NOT NULL CHECK (state IN ('pending', 'retracted')),
    retraction_intent_sha256 TEXT NOT NULL CHECK (
        length(retraction_intent_sha256) = 64
        AND retraction_intent_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    first_observed_at INTEGER NOT NULL CHECK (first_observed_at > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= first_observed_at),
    retracted_map_epoch INTEGER,
    retracted_epoch_id TEXT CHECK (
        retracted_epoch_id IS NULL
        OR (
            length(retracted_epoch_id) = 64
            AND retracted_epoch_id NOT GLOB '*[^0-9a-f]*'
        )
    ),
    retracted_root_hash TEXT CHECK (
        retracted_root_hash IS NULL
        OR (
            length(retracted_root_hash) = 64
            AND retracted_root_hash NOT GLOB '*[^0-9a-f]*'
        )
    ),
    PRIMARY KEY (feed_id, finding_id),
    FOREIGN KEY (feed_id, operator_id)
        REFERENCES finding_status_feeds(feed_id, operator_id),
    FOREIGN KEY (feed_id, retracted_map_epoch)
        REFERENCES finding_status_epochs(feed_id, map_epoch),
    CHECK (
        (state = 'pending'
            AND retracted_map_epoch IS NULL
            AND retracted_epoch_id IS NULL
            AND retracted_root_hash IS NULL)
        OR
        (state = 'retracted'
            AND retracted_map_epoch IS NOT NULL
            AND retracted_epoch_id IS NOT NULL
            AND retracted_root_hash IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS finding_status_states_by_state
    ON finding_status_states(feed_id, state, finding_id);

CREATE TRIGGER IF NOT EXISTS finding_status_states_sticky
BEFORE UPDATE ON finding_status_states
WHEN NEW.feed_id <> OLD.feed_id
  OR NEW.operator_id <> OLD.operator_id
  OR NEW.finding_id <> OLD.finding_id
  OR NEW.retraction_intent_sha256 <> OLD.retraction_intent_sha256
  OR NEW.first_observed_at <> OLD.first_observed_at
  OR NOT (OLD.state = 'pending' AND NEW.state = 'retracted')
BEGIN
    SELECT RAISE(ABORT, 'finding status is sticky');
END;

CREATE TRIGGER IF NOT EXISTS finding_status_states_no_delete
BEFORE DELETE ON finding_status_states
BEGIN
    SELECT RAISE(ABORT, 'finding status must be retained');
END;

CREATE TABLE IF NOT EXISTS finding_status_leaves (
    feed_id TEXT NOT NULL,
    operator_id TEXT NOT NULL,
    finding_id TEXT NOT NULL
        CHECK (length(finding_id) = 64 AND finding_id NOT GLOB '*[^0-9a-f]*'),
    key_domain_nonce INTEGER NOT NULL
        CHECK (key_domain_nonce = 3318287169837494),
    status_value_sha256 TEXT NOT NULL CHECK (
        length(status_value_sha256) = 64
        AND status_value_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    status_value_bytes BLOB NOT NULL CHECK (
        typeof(status_value_bytes) = 'blob'
        AND length(status_value_bytes) BETWEEN 1 AND 4096
    ),
    retraction_intent_sha256 TEXT NOT NULL CHECK (
        length(retraction_intent_sha256) = 64
        AND retraction_intent_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    local_intent_id TEXT,
    first_map_epoch INTEGER NOT NULL CHECK (first_map_epoch > 0),
    first_epoch_id TEXT NOT NULL
        CHECK (length(first_epoch_id) = 64 AND first_epoch_id NOT GLOB '*[^0-9a-f]*'),
    recorded_at INTEGER NOT NULL CHECK (recorded_at > 0),
    PRIMARY KEY (feed_id, finding_id),
    FOREIGN KEY (feed_id, operator_id)
        REFERENCES finding_status_feeds(feed_id, operator_id),
    FOREIGN KEY (feed_id, first_map_epoch)
        REFERENCES finding_status_epochs(feed_id, map_epoch),
    FOREIGN KEY (local_intent_id)
        REFERENCES finding_retraction_intents(intent_id)
);

CREATE INDEX IF NOT EXISTS finding_status_leaves_by_epoch
    ON finding_status_leaves(feed_id, first_map_epoch, finding_id);

CREATE TRIGGER IF NOT EXISTS finding_status_leaves_immutable
BEFORE UPDATE ON finding_status_leaves
BEGIN
    SELECT RAISE(ABORT, 'finding status leaf is immutable');
END;

CREATE TRIGGER IF NOT EXISTS finding_status_leaves_no_delete
BEFORE DELETE ON finding_status_leaves
BEGIN
    SELECT RAISE(ABORT, 'finding status leaf must be retained');
END;

CREATE TABLE IF NOT EXISTS finding_status_proofs (
    feed_id TEXT NOT NULL,
    operator_id TEXT NOT NULL,
    finding_id TEXT NOT NULL
        CHECK (length(finding_id) = 64 AND finding_id NOT GLOB '*[^0-9a-f]*'),
    key_domain_nonce INTEGER NOT NULL
        CHECK (key_domain_nonce = 3318287169837494),
    map_epoch INTEGER NOT NULL CHECK (map_epoch > 0),
    epoch_id TEXT NOT NULL
        CHECK (length(epoch_id) = 64 AND epoch_id NOT GLOB '*[^0-9a-f]*'),
    root_hash TEXT NOT NULL
        CHECK (length(root_hash) = 64 AND root_hash NOT GLOB '*[^0-9a-f]*'),
    proof_kind TEXT NOT NULL CHECK (proof_kind IN ('inclusion', 'non_inclusion')),
    proof_sha256 TEXT NOT NULL CHECK (
        length(proof_sha256) = 64 AND proof_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    proof_bytes BLOB NOT NULL CHECK (
        typeof(proof_bytes) = 'blob'
        AND length(proof_bytes) BETWEEN 1 AND 262144
    ),
    status_value_sha256 TEXT CHECK (
        status_value_sha256 IS NULL
        OR (
            length(status_value_sha256) = 64
            AND status_value_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    status_value_bytes BLOB CHECK (
        status_value_bytes IS NULL
        OR (
            typeof(status_value_bytes) = 'blob'
            AND length(status_value_bytes) BETWEEN 1 AND 4096
        )
    ),
    retraction_intent_sha256 TEXT CHECK (
        retraction_intent_sha256 IS NULL
        OR (
            length(retraction_intent_sha256) = 64
            AND retraction_intent_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    checked_at INTEGER NOT NULL CHECK (checked_at > 0),
    valid_until INTEGER NOT NULL CHECK (valid_until > checked_at),
    recorded_at INTEGER NOT NULL CHECK (recorded_at >= checked_at),
    PRIMARY KEY (feed_id, finding_id, map_epoch),
    FOREIGN KEY (feed_id, operator_id)
        REFERENCES finding_status_feeds(feed_id, operator_id),
    FOREIGN KEY (feed_id, map_epoch)
        REFERENCES finding_status_epochs(feed_id, map_epoch),
    CHECK (
        (proof_kind = 'non_inclusion'
            AND status_value_sha256 IS NULL
            AND status_value_bytes IS NULL
            AND retraction_intent_sha256 IS NULL)
        OR
        (proof_kind = 'inclusion'
            AND status_value_sha256 IS NOT NULL
            AND status_value_bytes IS NOT NULL
            AND retraction_intent_sha256 IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS finding_status_proofs_latest
    ON finding_status_proofs(feed_id, finding_id, map_epoch DESC);

CREATE TRIGGER IF NOT EXISTS finding_status_proofs_immutable
BEFORE UPDATE ON finding_status_proofs
BEGIN
    SELECT RAISE(ABORT, 'finding status proof is immutable');
END;

CREATE TRIGGER IF NOT EXISTS finding_status_proofs_no_delete
BEFORE DELETE ON finding_status_proofs
BEGIN
    SELECT RAISE(ABORT, 'finding status proof must be retained');
END;

-- Immutable local history for the complete status projection. Every status
-- mutation appends one row here and one exact reference in the authority-wide
-- commit chain before the transaction can commit.
CREATE TABLE IF NOT EXISTS finding_status_projection_commits (
    projection_sequence INTEGER PRIMARY KEY CHECK (projection_sequence > 0),
    mutation_kind TEXT NOT NULL CHECK (mutation_kind = 'finding_status_write'),
    snapshot_digest TEXT NOT NULL CHECK (
        length(snapshot_digest) = 64
        AND snapshot_digest NOT GLOB '*[^0-9a-f]*'
    ),
    previous_commit_digest TEXT NOT NULL CHECK (
        length(previous_commit_digest) = 64
        AND previous_commit_digest NOT GLOB '*[^0-9a-f]*'
    ),
    commit_digest TEXT NOT NULL UNIQUE CHECK (
        length(commit_digest) = 64
        AND commit_digest NOT GLOB '*[^0-9a-f]*'
    )
);

CREATE TRIGGER IF NOT EXISTS finding_status_projection_commits_immutable
BEFORE UPDATE ON finding_status_projection_commits
BEGIN
    SELECT RAISE(ABORT, 'finding status projection commit is immutable');
END;

CREATE TRIGGER IF NOT EXISTS finding_status_projection_commits_no_delete
BEFORE DELETE ON finding_status_projection_commits
BEGIN
    SELECT RAISE(ABORT, 'finding status projection commit is immutable');
END;
