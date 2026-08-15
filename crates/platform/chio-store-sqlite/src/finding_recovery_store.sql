CREATE TABLE IF NOT EXISTS finding_recovery_issuances (
    recovery_id TEXT NOT NULL PRIMARY KEY
        CHECK (length(recovery_id) = 64 AND recovery_id NOT GLOB '*[^0-9a-f]*'),
    finding_id TEXT NOT NULL
        CHECK (length(finding_id) = 64 AND finding_id NOT GLOB '*[^0-9a-f]*'),
    listing_id TEXT NOT NULL CHECK (length(listing_id) BETWEEN 1 AND 512),
    original_capability_id TEXT NOT NULL
        CHECK (length(original_capability_id) BETWEEN 1 AND 512),
    original_delivery_receipt_id TEXT NOT NULL
        CHECK (length(original_delivery_receipt_id) BETWEEN 1 AND 512),
    purchase_key TEXT NOT NULL REFERENCES purchase_records(purchase_key),
    original_subject_key_hex TEXT NOT NULL CHECK (
        length(original_subject_key_hex) = 64
        AND original_subject_key_hex NOT GLOB '*[^0-9a-f]*'
    ),
    max_recoveries INTEGER NOT NULL CHECK (max_recoveries BETWEEN 1 AND 8),
    issued_at INTEGER NOT NULL CHECK (issued_at > 0)
);

CREATE TRIGGER IF NOT EXISTS finding_recovery_issuances_immutable
BEFORE UPDATE ON finding_recovery_issuances
BEGIN
    SELECT RAISE(ABORT, 'finding recovery issuance is immutable');
END;

CREATE TRIGGER IF NOT EXISTS finding_recovery_issuances_no_delete
BEFORE DELETE ON finding_recovery_issuances
BEGIN
    SELECT RAISE(ABORT, 'finding recovery issuance must be retained');
END;

CREATE TABLE IF NOT EXISTS finding_recovery_attempts (
    recovery_id TEXT NOT NULL REFERENCES finding_recovery_issuances(recovery_id),
    request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 512),
    attempt_ordinal INTEGER NOT NULL CHECK (attempt_ordinal > 0),
    reserved_at INTEGER NOT NULL CHECK (reserved_at > 0),
    PRIMARY KEY (recovery_id, request_id),
    UNIQUE (recovery_id, attempt_ordinal)
);

CREATE TRIGGER IF NOT EXISTS finding_recovery_attempts_immutable
BEFORE UPDATE ON finding_recovery_attempts
BEGIN
    SELECT RAISE(ABORT, 'finding recovery attempt is immutable');
END;

CREATE TRIGGER IF NOT EXISTS finding_recovery_attempts_no_delete
BEFORE DELETE ON finding_recovery_attempts
BEGIN
    SELECT RAISE(ABORT, 'finding recovery attempt must be retained');
END;

CREATE TABLE IF NOT EXISTS finding_recovery_receipt_lineage (
    recovery_receipt_id TEXT NOT NULL PRIMARY KEY
        CHECK (length(recovery_receipt_id) BETWEEN 1 AND 512),
    recovery_id TEXT NOT NULL REFERENCES finding_recovery_issuances(recovery_id),
    original_delivery_receipt_id TEXT NOT NULL
        CHECK (length(original_delivery_receipt_id) BETWEEN 1 AND 512),
    purchase_key TEXT NOT NULL
        CHECK (length(purchase_key) = 64 AND purchase_key NOT GLOB '*[^0-9a-f]*'),
    recorded_at INTEGER NOT NULL CHECK (recorded_at > 0)
);

CREATE INDEX IF NOT EXISTS finding_recovery_lineage_by_origin
    ON finding_recovery_receipt_lineage(original_delivery_receipt_id, recovery_receipt_id);

CREATE TRIGGER IF NOT EXISTS finding_recovery_receipt_lineage_immutable
BEFORE UPDATE ON finding_recovery_receipt_lineage
BEGIN
    SELECT RAISE(ABORT, 'finding recovery receipt lineage is immutable');
END;

CREATE TRIGGER IF NOT EXISTS finding_recovery_receipt_lineage_no_delete
BEFORE DELETE ON finding_recovery_receipt_lineage
BEGIN
    SELECT RAISE(ABORT, 'finding recovery receipt lineage must be retained');
END;
