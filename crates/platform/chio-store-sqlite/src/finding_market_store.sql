CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT NOT NULL PRIMARY KEY
        CHECK (length(finding_id) = 64 AND finding_id NOT GLOB '*[^0-9a-f]*'),
    artifact_json TEXT NOT NULL CHECK (
        typeof(artifact_json) = 'text'
        AND length(artifact_json) BETWEEN 1 AND 262144
    ),
    artifact_sha256 TEXT NOT NULL
        CHECK (length(artifact_sha256) = 64 AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'),
    topic TEXT NOT NULL CHECK (length(topic) BETWEEN 1 AND 120),
    context_sha256 TEXT NOT NULL
        CHECK (length(context_sha256) = 64 AND context_sha256 NOT GLOB '*[^0-9a-f]*'),
    issued_at INTEGER NOT NULL CHECK (issued_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > issued_at),
    indexed_at INTEGER NOT NULL CHECK (indexed_at > 0)
);

CREATE INDEX IF NOT EXISTS findings_topic
    ON findings(topic, finding_id);

CREATE INDEX IF NOT EXISTS findings_context
    ON findings(context_sha256, finding_id);

CREATE TRIGGER IF NOT EXISTS findings_immutable
BEFORE UPDATE ON findings
BEGIN
    SELECT RAISE(ABORT, 'published finding is immutable');
END;

CREATE TRIGGER IF NOT EXISTS findings_no_delete
BEFORE DELETE ON findings
BEGIN
    SELECT RAISE(ABORT, 'published finding must be retained');
END;

CREATE TABLE IF NOT EXISTS recipe_blobs (
    canonical_sha256 TEXT NOT NULL PRIMARY KEY
        CHECK (length(canonical_sha256) = 64 AND canonical_sha256 NOT GLOB '*[^0-9a-f]*'),
    blob_bytes BLOB NOT NULL CHECK (
        typeof(blob_bytes) = 'blob'
        AND length(blob_bytes) BETWEEN 1 AND 1048576
    ),
    stored_at INTEGER NOT NULL CHECK (stored_at > 0)
);

CREATE TRIGGER IF NOT EXISTS recipe_blobs_immutable
BEFORE UPDATE ON recipe_blobs
BEGIN
    SELECT RAISE(ABORT, 'recipe blob is immutable');
END;

CREATE TRIGGER IF NOT EXISTS recipe_blobs_no_delete
BEFORE DELETE ON recipe_blobs
BEGIN
    SELECT RAISE(ABORT, 'recipe blob must be retained through the audit horizon');
END;

CREATE TABLE IF NOT EXISTS collateral_allocations (
    allocation_id TEXT NOT NULL PRIMARY KEY
        CHECK (length(allocation_id) = 64 AND allocation_id NOT GLOB '*[^0-9a-f]*'),
    seller_hex TEXT NOT NULL CHECK (seller_hex <> ''),
    finding_id TEXT NOT NULL
        CHECK (length(finding_id) = 64 AND finding_id NOT GLOB '*[^0-9a-f]*'),
    listing_id TEXT NOT NULL CHECK (length(listing_id) BETWEEN 1 AND 512),
    backing_envelope_sha256 TEXT NOT NULL CHECK (
        length(backing_envelope_sha256) = 64
        AND backing_envelope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    backing_envelope_json TEXT NOT NULL CHECK (
        typeof(backing_envelope_json) = 'text'
        AND length(backing_envelope_json) BETWEEN 1 AND 262144
    ),
    currency TEXT NOT NULL
        CHECK (length(currency) = 3 AND currency NOT GLOB '*[^A-Z]*'),
    locked_units INTEGER NOT NULL CHECK (locked_units > 0),
    maximum_sale_exposure_units INTEGER NOT NULL CHECK (
        maximum_sale_exposure_units > 0
        AND maximum_sale_exposure_units <= locked_units
    ),
    expires_at INTEGER NOT NULL CHECK (expires_at > 0),
    accepted_at INTEGER NOT NULL
        CHECK (accepted_at > 0 AND accepted_at < expires_at),
    state TEXT NOT NULL
        CHECK (state IN ('live', 'consumed', 'expired', 'released'))
);

CREATE UNIQUE INDEX IF NOT EXISTS collateral_allocations_live_listing
    ON collateral_allocations(seller_hex, finding_id, listing_id)
    WHERE state = 'live';

CREATE INDEX IF NOT EXISTS collateral_allocations_listing
    ON collateral_allocations(finding_id, listing_id, state);

CREATE TRIGGER IF NOT EXISTS collateral_allocations_immutable_identity
BEFORE UPDATE ON collateral_allocations
WHEN NEW.allocation_id <> OLD.allocation_id
  OR NEW.seller_hex <> OLD.seller_hex
  OR NEW.finding_id <> OLD.finding_id
  OR NEW.listing_id <> OLD.listing_id
  OR NEW.backing_envelope_sha256 <> OLD.backing_envelope_sha256
  OR NEW.backing_envelope_json <> OLD.backing_envelope_json
  OR NEW.currency <> OLD.currency
  OR NEW.locked_units <> OLD.locked_units
  OR NEW.maximum_sale_exposure_units <> OLD.maximum_sale_exposure_units
  OR NEW.expires_at <> OLD.expires_at
  OR NEW.accepted_at <> OLD.accepted_at
BEGIN
    SELECT RAISE(ABORT, 'collateral allocation identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS collateral_allocations_lifecycle
BEFORE UPDATE OF state ON collateral_allocations
WHEN NOT (OLD.state = 'live' AND NEW.state IN ('consumed', 'expired', 'released'))
BEGIN
    SELECT RAISE(ABORT, 'collateral allocation leaves live exactly once');
END;

CREATE TRIGGER IF NOT EXISTS collateral_allocations_no_delete
BEFORE DELETE ON collateral_allocations
BEGIN
    SELECT RAISE(ABORT, 'collateral allocation must be retained');
END;

CREATE TABLE IF NOT EXISTS fee_events (
    idempotency_key TEXT NOT NULL PRIMARY KEY
        CHECK (length(idempotency_key) BETWEEN 1 AND 1024),
    fee_schedule_envelope_sha256 TEXT NOT NULL CHECK (
        length(fee_schedule_envelope_sha256) = 64
        AND fee_schedule_envelope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    event_kind TEXT NOT NULL
        CHECK (event_kind IN ('publication', 'participation_epoch')),
    epoch_index INTEGER NOT NULL CHECK (epoch_index >= 0),
    finding_id TEXT NOT NULL
        CHECK (length(finding_id) = 64 AND finding_id NOT GLOB '*[^0-9a-f]*'),
    listing_id TEXT NOT NULL CHECK (length(listing_id) BETWEEN 1 AND 512),
    payer TEXT NOT NULL CHECK (payer <> ''),
    amount_units INTEGER NOT NULL CHECK (amount_units > 0),
    currency TEXT NOT NULL
        CHECK (length(currency) = 3 AND currency NOT GLOB '*[^A-Z]*'),
    pool_principal_id TEXT NOT NULL CHECK (pool_principal_id <> ''),
    rail_destination TEXT NOT NULL CHECK (rail_destination <> ''),
    instruction_sha256 TEXT NOT NULL CHECK (
        length(instruction_sha256) = 64
        AND instruction_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    observation_sha256 TEXT CHECK (
        observation_sha256 IS NULL
        OR (length(observation_sha256) = 64
            AND observation_sha256 NOT GLOB '*[^0-9a-f]*')
    ),
    state TEXT NOT NULL CHECK (state IN ('intent', 'reconciled', 'failed')),
    CHECK (event_kind <> 'publication' OR epoch_index = 0),
    CHECK ((state = 'reconciled') = (observation_sha256 IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS fee_events_listing_epochs
    ON fee_events(finding_id, listing_id, event_kind, state, epoch_index);

CREATE TRIGGER IF NOT EXISTS fee_events_immutable_identity
BEFORE UPDATE ON fee_events
WHEN NEW.idempotency_key <> OLD.idempotency_key
  OR NEW.fee_schedule_envelope_sha256 <> OLD.fee_schedule_envelope_sha256
  OR NEW.event_kind <> OLD.event_kind
  OR NEW.epoch_index <> OLD.epoch_index
  OR NEW.finding_id <> OLD.finding_id
  OR NEW.listing_id <> OLD.listing_id
  OR NEW.payer <> OLD.payer
  OR NEW.amount_units <> OLD.amount_units
  OR NEW.currency <> OLD.currency
  OR NEW.pool_principal_id <> OLD.pool_principal_id
  OR NEW.rail_destination <> OLD.rail_destination
  OR NEW.instruction_sha256 <> OLD.instruction_sha256
BEGIN
    SELECT RAISE(ABORT, 'fee event identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS fee_events_lifecycle
BEFORE UPDATE OF state, observation_sha256 ON fee_events
WHEN NOT (
    (OLD.state = 'intent' AND NEW.state IN ('reconciled', 'failed'))
    OR (OLD.state = 'failed' AND NEW.state = 'reconciled')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid fee event lifecycle');
END;

CREATE TRIGGER IF NOT EXISTS fee_events_no_delete
BEFORE DELETE ON fee_events
BEGIN
    SELECT RAISE(ABORT, 'fee event is a charge tombstone');
END;

CREATE TABLE IF NOT EXISTS finding_activation_attempts (
    admission_id TEXT NOT NULL PRIMARY KEY
        CHECK (length(admission_id) = 64 AND admission_id NOT GLOB '*[^0-9a-f]*'),
    finding_id TEXT NOT NULL
        CHECK (length(finding_id) = 64 AND finding_id NOT GLOB '*[^0-9a-f]*'),
    listing_id TEXT NOT NULL CHECK (length(listing_id) BETWEEN 1 AND 512),
    backing_allocation_id TEXT NOT NULL CHECK (
        length(backing_allocation_id) = 64
        AND backing_allocation_id NOT GLOB '*[^0-9a-f]*'
    ),
    admission_envelope_sha256 TEXT NOT NULL CHECK (
        length(admission_envelope_sha256) = 64
        AND admission_envelope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    admission_envelope_json TEXT NOT NULL CHECK (
        typeof(admission_envelope_json) = 'text'
        AND length(admission_envelope_json) BETWEEN 1 AND 262144
    ),
    prepared_at INTEGER NOT NULL CHECK (prepared_at > 0),
    state TEXT NOT NULL CHECK (state IN ('prepared', 'activated')),
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id),
    FOREIGN KEY (backing_allocation_id)
        REFERENCES collateral_allocations(allocation_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS finding_activation_attempts_prepared_finding
    ON finding_activation_attempts(finding_id) WHERE state = 'prepared';

CREATE UNIQUE INDEX IF NOT EXISTS finding_activation_attempts_prepared_listing
    ON finding_activation_attempts(listing_id) WHERE state = 'prepared';

CREATE TRIGGER IF NOT EXISTS finding_activation_attempts_immutable_identity
BEFORE UPDATE ON finding_activation_attempts
WHEN NEW.admission_id <> OLD.admission_id
  OR NEW.finding_id <> OLD.finding_id
  OR NEW.listing_id <> OLD.listing_id
  OR NEW.backing_allocation_id <> OLD.backing_allocation_id
  OR NEW.admission_envelope_sha256 <> OLD.admission_envelope_sha256
  OR NEW.admission_envelope_json <> OLD.admission_envelope_json
  OR NEW.prepared_at <> OLD.prepared_at
BEGIN
    SELECT RAISE(ABORT, 'finding activation attempt identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS finding_activation_attempts_lifecycle
BEFORE UPDATE OF state ON finding_activation_attempts
WHEN NOT (OLD.state = 'prepared' AND NEW.state = 'activated')
BEGIN
    SELECT RAISE(ABORT, 'finding activation attempt only moves prepared to activated');
END;

CREATE TRIGGER IF NOT EXISTS finding_activation_attempts_no_delete
BEFORE DELETE ON finding_activation_attempts
BEGIN
    SELECT RAISE(ABORT, 'finding activation attempt must be retained');
END;

CREATE TABLE IF NOT EXISTS admissions (
    admission_id TEXT NOT NULL PRIMARY KEY
        CHECK (length(admission_id) = 64 AND admission_id NOT GLOB '*[^0-9a-f]*'),
    finding_id TEXT NOT NULL
        CHECK (length(finding_id) = 64 AND finding_id NOT GLOB '*[^0-9a-f]*'),
    listing_id TEXT NOT NULL CHECK (length(listing_id) BETWEEN 1 AND 512),
    backing_allocation_id TEXT NOT NULL CHECK (
        length(backing_allocation_id) = 64
        AND backing_allocation_id NOT GLOB '*[^0-9a-f]*'
    ),
    admission_envelope_sha256 TEXT NOT NULL CHECK (
        length(admission_envelope_sha256) = 64
        AND admission_envelope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    admission_envelope_json TEXT NOT NULL CHECK (
        typeof(admission_envelope_json) = 'text'
        AND length(admission_envelope_json) BETWEEN 1 AND 262144
    ),
    expires_at INTEGER NOT NULL CHECK (expires_at > 0),
    activated_at INTEGER NOT NULL CHECK (activated_at > 0),
    state TEXT NOT NULL CHECK (state IN ('active', 'superseded')),
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id),
    FOREIGN KEY (backing_allocation_id)
        REFERENCES collateral_allocations(allocation_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS admissions_active_finding
    ON admissions(finding_id) WHERE state = 'active';

CREATE UNIQUE INDEX IF NOT EXISTS admissions_active_listing
    ON admissions(listing_id) WHERE state = 'active';

CREATE TRIGGER IF NOT EXISTS admissions_immutable_identity
BEFORE UPDATE ON admissions
WHEN NEW.admission_id <> OLD.admission_id
  OR NEW.finding_id <> OLD.finding_id
  OR NEW.listing_id <> OLD.listing_id
  OR NEW.backing_allocation_id <> OLD.backing_allocation_id
  OR NEW.admission_envelope_sha256 <> OLD.admission_envelope_sha256
  OR NEW.admission_envelope_json <> OLD.admission_envelope_json
  OR NEW.expires_at <> OLD.expires_at
  OR NEW.activated_at <> OLD.activated_at
BEGIN
    SELECT RAISE(ABORT, 'admission identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS admissions_lifecycle
BEFORE UPDATE OF state ON admissions
WHEN NOT (OLD.state = 'active' AND NEW.state = 'superseded')
BEGIN
    SELECT RAISE(ABORT, 'admission state only moves active to superseded');
END;

CREATE TRIGGER IF NOT EXISTS admissions_no_delete
BEFORE DELETE ON admissions
BEGIN
    SELECT RAISE(ABORT, 'admission must be retained');
END;
