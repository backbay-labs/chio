ALTER TABLE chio_finding_market_aggregate_events
    ADD CONSTRAINT chio_finding_market_aggregate_events_revision_digest_v1
    UNIQUE (tenant_id, aggregate_kind, aggregate_id, revision, event_sha256);

CREATE TABLE chio_finding_market_aggregate_checkpoints (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    checkpoint_sha256 CHAR(64) NOT NULL,
    aggregate_kind TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    event_sha256 CHAR(64) NOT NULL,
    previous_checkpoint_sha256 CHAR(64),
    signer_key_hex CHAR(64) NOT NULL,
    checkpoint_envelope_json BYTEA NOT NULL,
    created_at BIGINT NOT NULL CHECK (created_at > 0),
    PRIMARY KEY (tenant_id, checkpoint_sha256),
    UNIQUE (tenant_id, aggregate_kind, aggregate_id, revision),
    CONSTRAINT chio_finding_market_aggregate_checkpoints_event_fk
        FOREIGN KEY (
            tenant_id, aggregate_kind, aggregate_id, revision, event_sha256
        ) REFERENCES chio_finding_market_aggregate_events (
            tenant_id, aggregate_kind, aggregate_id, revision, event_sha256
        ),
    CONSTRAINT chio_finding_market_aggregate_checkpoints_predecessor_fk
        FOREIGN KEY (tenant_id, previous_checkpoint_sha256)
        REFERENCES chio_finding_market_aggregate_checkpoints
            (tenant_id, checkpoint_sha256),
    CONSTRAINT chio_finding_market_aggregate_checkpoints_kind_v1 CHECK (
        aggregate_kind IN (
            'finding', 'listing', 'admission', 'purchase',
            'purchase_terminal', 'failed_delivery', 'challenge',
            'challenge_outcome', 'liability', 'appeal', 'penalty',
            'enforcement', 'settlement', 'status_epoch', 'audit_round'
        )
    ),
    CONSTRAINT chio_finding_market_aggregate_checkpoints_identifier_v1 CHECK (
        octet_length(aggregate_id) BETWEEN 1 AND 256
        AND aggregate_id !~ '[^A-Za-z0-9_.:/-]'
    ),
    CONSTRAINT chio_finding_market_aggregate_checkpoints_digest_v1 CHECK (
        checkpoint_sha256 !~ '[^0-9a-f]'
        AND event_sha256 !~ '[^0-9a-f]'
        AND signer_key_hex !~ '[^0-9a-f]'
        AND (
            previous_checkpoint_sha256 IS NULL
            OR previous_checkpoint_sha256 !~ '[^0-9a-f]'
        )
    ),
    CONSTRAINT chio_finding_market_aggregate_checkpoints_envelope_size_v1 CHECK (
        octet_length(checkpoint_envelope_json) BETWEEN 1 AND 4194304
    )
);

CREATE INDEX chio_finding_market_aggregate_checkpoints_latest
ON chio_finding_market_aggregate_checkpoints
    (tenant_id, aggregate_kind, aggregate_id, revision DESC);

ALTER TABLE chio_finding_market_aggregate_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE chio_finding_market_aggregate_checkpoints FORCE ROW LEVEL SECURITY;

CREATE POLICY chio_finding_market_aggregate_checkpoints_tenant_isolation
ON chio_finding_market_aggregate_checkpoints
USING (tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), ''))
WITH CHECK (tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), ''));

CREATE TRIGGER chio_finding_market_aggregate_checkpoints_immutable
BEFORE UPDATE OR DELETE ON chio_finding_market_aggregate_checkpoints
FOR EACH ROW EXECUTE FUNCTION chio_finding_market_reject_immutable_mutation();

REVOKE UPDATE, DELETE ON chio_finding_market_aggregate_checkpoints FROM PUBLIC;
