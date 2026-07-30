CREATE TABLE IF NOT EXISTS purchase_reservations (
    reservation_id TEXT NOT NULL PRIMARY KEY
        CHECK (length(reservation_id) BETWEEN 1 AND 512),
    purchase_intent_id TEXT NOT NULL UNIQUE
        CHECK (length(purchase_intent_id) BETWEEN 1 AND 512),
    authoritative_payment_operation_id TEXT NOT NULL UNIQUE
        CHECK (length(authoritative_payment_operation_id) BETWEEN 1 AND 512),
    payer_hex TEXT NOT NULL
        CHECK (length(payer_hex) = 64 AND payer_hex NOT GLOB '*[^0-9a-f]*'),
    agent_id TEXT NOT NULL CHECK (length(agent_id) BETWEEN 1 AND 512),
    finding_id TEXT NOT NULL
        CHECK (length(finding_id) = 64 AND finding_id NOT GLOB '*[^0-9a-f]*'),
    listing_id TEXT NOT NULL CHECK (length(listing_id) BETWEEN 1 AND 512),
    bid_envelope_sha256 TEXT NOT NULL CHECK (
        length(bid_envelope_sha256) = 64
        AND bid_envelope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    ask_digest TEXT NOT NULL
        CHECK (length(ask_digest) = 64 AND ask_digest NOT GLOB '*[^0-9a-f]*'),
    admission_envelope_sha256 TEXT NOT NULL CHECK (
        length(admission_envelope_sha256) = 64
        AND admission_envelope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    amount_units INTEGER NOT NULL CHECK (amount_units > 0),
    currency TEXT NOT NULL
        CHECK (length(currency) = 3 AND currency NOT GLOB '*[^A-Z]*'),
    expires_at INTEGER NOT NULL CHECK (expires_at > 0),
    state TEXT NOT NULL CHECK (
        state IN ('open', 'slot_reserved', 'consumed', 'released', 'expired')
    ),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at)
);

CREATE INDEX IF NOT EXISTS purchase_reservations_listing
    ON purchase_reservations(listing_id, state, reservation_id);

CREATE INDEX IF NOT EXISTS purchase_reservations_expiry
    ON purchase_reservations(state, expires_at, reservation_id);

CREATE TRIGGER IF NOT EXISTS purchase_reservations_immutable_identity
BEFORE UPDATE ON purchase_reservations
WHEN NEW.reservation_id <> OLD.reservation_id
  OR NEW.purchase_intent_id <> OLD.purchase_intent_id
  OR NEW.authoritative_payment_operation_id <> OLD.authoritative_payment_operation_id
  OR NEW.payer_hex <> OLD.payer_hex
  OR NEW.agent_id <> OLD.agent_id
  OR NEW.finding_id <> OLD.finding_id
  OR NEW.listing_id <> OLD.listing_id
  OR NEW.bid_envelope_sha256 <> OLD.bid_envelope_sha256
  OR NEW.ask_digest <> OLD.ask_digest
  OR NEW.admission_envelope_sha256 <> OLD.admission_envelope_sha256
  OR NEW.amount_units <> OLD.amount_units
  OR NEW.currency <> OLD.currency
  OR NEW.expires_at <> OLD.expires_at
  OR NEW.created_at <> OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'purchase reservation identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS purchase_reservations_lifecycle
BEFORE UPDATE OF state ON purchase_reservations
WHEN NOT (
    (OLD.state = 'open' AND NEW.state IN ('slot_reserved', 'released', 'expired'))
    OR (OLD.state = 'slot_reserved'
        AND NEW.state IN ('consumed', 'released', 'expired'))
)
BEGIN
    SELECT RAISE(ABORT, 'invalid purchase reservation lifecycle');
END;

CREATE TRIGGER IF NOT EXISTS purchase_reservations_no_delete
BEFORE DELETE ON purchase_reservations
BEGIN
    SELECT RAISE(ABORT, 'purchase reservation must be retained');
END;

CREATE TABLE IF NOT EXISTS seller_exposure_encumbrances (
    encumbrance_id TEXT NOT NULL PRIMARY KEY
        CHECK (length(encumbrance_id) BETWEEN 1 AND 512),
    allocation_id TEXT NOT NULL
        CHECK (length(allocation_id) = 64 AND allocation_id NOT GLOB '*[^0-9a-f]*'),
    reservation_id TEXT NOT NULL UNIQUE
        REFERENCES purchase_reservations(reservation_id),
    amount_units INTEGER NOT NULL CHECK (amount_units > 0),
    currency TEXT NOT NULL
        CHECK (length(currency) = 3 AND currency NOT GLOB '*[^A-Z]*'),
    state TEXT NOT NULL CHECK (state IN ('open', 'released', 'retained')),
    retention_expires_at INTEGER
        CHECK (retention_expires_at IS NULL OR retention_expires_at > 0),
    opened_at INTEGER NOT NULL CHECK (opened_at > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= opened_at),
    CHECK ((state = 'retained') = (retention_expires_at IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS seller_exposure_encumbrances_allocation
    ON seller_exposure_encumbrances(allocation_id, state);

CREATE TRIGGER IF NOT EXISTS seller_exposure_encumbrances_immutable_identity
BEFORE UPDATE ON seller_exposure_encumbrances
WHEN NEW.encumbrance_id <> OLD.encumbrance_id
  OR NEW.allocation_id <> OLD.allocation_id
  OR NEW.reservation_id <> OLD.reservation_id
  OR NEW.amount_units <> OLD.amount_units
  OR NEW.currency <> OLD.currency
  OR NEW.opened_at <> OLD.opened_at
BEGIN
    SELECT RAISE(ABORT, 'seller exposure encumbrance identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS seller_exposure_encumbrances_lifecycle
BEFORE UPDATE OF state, retention_expires_at ON seller_exposure_encumbrances
WHEN NOT (OLD.state = 'open' AND NEW.state IN ('released', 'retained'))
BEGIN
    SELECT RAISE(ABORT, 'seller exposure encumbrance leaves open exactly once');
END;

CREATE TRIGGER IF NOT EXISTS seller_exposure_encumbrances_no_delete
BEFORE DELETE ON seller_exposure_encumbrances
BEGIN
    SELECT RAISE(ABORT, 'seller exposure encumbrance must be retained');
END;

CREATE TABLE IF NOT EXISTS pending_purchase_slots (
    listing_id TEXT NOT NULL CHECK (length(listing_id) BETWEEN 1 AND 512),
    slot_ordinal INTEGER NOT NULL CHECK (slot_ordinal > 0),
    reservation_id TEXT NOT NULL UNIQUE
        REFERENCES purchase_reservations(reservation_id),
    state TEXT NOT NULL
        CHECK (state IN ('reserved', 'closed_record', 'closed_deny')),
    reserved_at INTEGER NOT NULL CHECK (reserved_at > 0),
    closed_at INTEGER CHECK (closed_at IS NULL OR closed_at >= reserved_at),
    PRIMARY KEY (listing_id, slot_ordinal),
    CHECK ((state = 'reserved') = (closed_at IS NULL))
);

CREATE INDEX IF NOT EXISTS pending_purchase_slots_open
    ON pending_purchase_slots(listing_id, state, slot_ordinal);

CREATE TRIGGER IF NOT EXISTS pending_purchase_slots_immutable_identity
BEFORE UPDATE ON pending_purchase_slots
WHEN NEW.listing_id <> OLD.listing_id
  OR NEW.slot_ordinal <> OLD.slot_ordinal
  OR NEW.reservation_id <> OLD.reservation_id
  OR NEW.reserved_at <> OLD.reserved_at
BEGIN
    SELECT RAISE(ABORT, 'pending purchase slot identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS pending_purchase_slots_lifecycle
BEFORE UPDATE OF state, closed_at ON pending_purchase_slots
WHEN NOT (
    OLD.state = 'reserved' AND NEW.state IN ('closed_record', 'closed_deny')
)
BEGIN
    SELECT RAISE(ABORT, 'pending purchase slot closes exactly once');
END;

CREATE TRIGGER IF NOT EXISTS pending_purchase_slots_no_delete
BEFORE DELETE ON pending_purchase_slots
BEGIN
    SELECT RAISE(ABORT, 'pending purchase slot must be retained');
END;

CREATE TABLE IF NOT EXISTS listing_sales_blocks (
    listing_id TEXT NOT NULL PRIMARY KEY
        CHECK (length(listing_id) BETWEEN 1 AND 512),
    blocked_at INTEGER NOT NULL CHECK (blocked_at > 0)
);

CREATE TRIGGER IF NOT EXISTS listing_sales_blocks_immutable
BEFORE UPDATE ON listing_sales_blocks
BEGIN
    SELECT RAISE(ABORT, 'listing sales block is immutable');
END;

CREATE TRIGGER IF NOT EXISTS listing_sales_blocks_no_delete
BEFORE DELETE ON listing_sales_blocks
BEGIN
    SELECT RAISE(ABORT, 'listing sales block must be retained');
END;

CREATE TABLE IF NOT EXISTS purchase_records (
    purchase_key TEXT NOT NULL PRIMARY KEY
        CHECK (length(purchase_key) = 64 AND purchase_key NOT GLOB '*[^0-9a-f]*'),
    reservation_id TEXT NOT NULL UNIQUE
        REFERENCES purchase_reservations(reservation_id),
    record_json BLOB NOT NULL CHECK (
        typeof(record_json) = 'blob'
        AND length(record_json) BETWEEN 1 AND 262144
    ),
    record_sha256 TEXT NOT NULL
        CHECK (length(record_sha256) = 64 AND record_sha256 NOT GLOB '*[^0-9a-f]*'),
    delivery_receipt_id TEXT NOT NULL
        CHECK (length(delivery_receipt_id) BETWEEN 1 AND 512),
    recorded_at INTEGER NOT NULL CHECK (recorded_at > 0)
);

CREATE TRIGGER IF NOT EXISTS purchase_records_immutable
BEFORE UPDATE ON purchase_records
BEGIN
    SELECT RAISE(ABORT, 'settled purchase record is immutable');
END;

CREATE TRIGGER IF NOT EXISTS purchase_records_no_delete
BEFORE DELETE ON purchase_records
BEGIN
    SELECT RAISE(ABORT, 'settled purchase record must be retained');
END;

CREATE TABLE IF NOT EXISTS failed_delivery_records (
    failed_delivery_id TEXT NOT NULL PRIMARY KEY
        CHECK (length(failed_delivery_id) BETWEEN 1 AND 512),
    reservation_id TEXT NOT NULL UNIQUE
        REFERENCES purchase_reservations(reservation_id),
    record_json BLOB NOT NULL CHECK (
        typeof(record_json) = 'blob'
        AND length(record_json) BETWEEN 1 AND 262144
    ),
    record_sha256 TEXT NOT NULL
        CHECK (length(record_sha256) = 64 AND record_sha256 NOT GLOB '*[^0-9a-f]*'),
    deny_receipt_id TEXT NOT NULL
        CHECK (length(deny_receipt_id) BETWEEN 1 AND 512),
    recorded_at INTEGER NOT NULL CHECK (recorded_at > 0)
);

CREATE TRIGGER IF NOT EXISTS failed_delivery_records_immutable
BEFORE UPDATE ON failed_delivery_records
BEGIN
    SELECT RAISE(ABORT, 'failed delivery record is immutable');
END;

CREATE TRIGGER IF NOT EXISTS failed_delivery_records_no_delete
BEFORE DELETE ON failed_delivery_records
BEGIN
    SELECT RAISE(ABORT, 'failed delivery record must be retained');
END;

CREATE TABLE IF NOT EXISTS payout_destinations (
    allocation_id TEXT NOT NULL
        CHECK (length(allocation_id) = 64 AND allocation_id NOT GLOB '*[^0-9a-f]*'),
    destination TEXT NOT NULL CHECK (
        length(destination) BETWEEN 3 AND 512
        AND destination GLOB '?*:?*'
    ),
    slot_index INTEGER NOT NULL CHECK (slot_index BETWEEN 0 AND 15),
    admitted_at INTEGER NOT NULL CHECK (admitted_at > 0),
    PRIMARY KEY (allocation_id, destination)
);

CREATE UNIQUE INDEX IF NOT EXISTS payout_destinations_slot
    ON payout_destinations(allocation_id, slot_index);

CREATE TRIGGER IF NOT EXISTS payout_destinations_immutable
BEFORE UPDATE ON payout_destinations
BEGIN
    SELECT RAISE(ABORT, 'admitted payout destination is immutable');
END;

CREATE TRIGGER IF NOT EXISTS payout_destinations_no_delete
BEFORE DELETE ON payout_destinations
BEGIN
    SELECT RAISE(ABORT, 'admitted payout destination must be retained');
END;
