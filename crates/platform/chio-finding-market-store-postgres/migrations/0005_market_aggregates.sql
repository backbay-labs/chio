CREATE TABLE IF NOT EXISTS chio_finding_market_aggregate_events (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    aggregate_kind TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    event_id TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    previous_event_sha256 CHAR(64),
    payload_sha256 CHAR(64) NOT NULL,
    payload_json BYTEA NOT NULL,
    event_sha256 CHAR(64) NOT NULL,
    committed_at BIGINT NOT NULL CHECK (committed_at > 0),
    PRIMARY KEY (tenant_id, aggregate_kind, aggregate_id, revision),
    UNIQUE (tenant_id, event_id),
    CHECK (
        (revision = 1 AND previous_event_sha256 IS NULL)
        OR (revision > 1 AND previous_event_sha256 IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS chio_finding_market_aggregate_heads (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    aggregate_kind TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    event_sha256 CHAR(64) NOT NULL,
    updated_at BIGINT NOT NULL CHECK (updated_at > 0),
    PRIMARY KEY (tenant_id, aggregate_kind, aggregate_id),
    CONSTRAINT chio_finding_market_aggregate_heads_event_fk
    FOREIGN KEY (tenant_id, aggregate_kind, aggregate_id, revision)
        REFERENCES chio_finding_market_aggregate_events
            (tenant_id, aggregate_kind, aggregate_id, revision)
);

DO $constraint$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chio_finding_market_aggregate_heads_event_fk'
          AND conrelid = 'chio_finding_market_aggregate_heads'::regclass
    ) THEN
        ALTER TABLE chio_finding_market_aggregate_heads
        ADD CONSTRAINT chio_finding_market_aggregate_heads_event_fk
        FOREIGN KEY (tenant_id, aggregate_kind, aggregate_id, revision)
        REFERENCES chio_finding_market_aggregate_events
            (tenant_id, aggregate_kind, aggregate_id, revision);
    END IF;
END
$constraint$;

CREATE INDEX IF NOT EXISTS chio_finding_market_aggregate_events_history
ON chio_finding_market_aggregate_events
    (tenant_id, aggregate_kind, aggregate_id, revision);

ALTER TABLE chio_finding_market_aggregate_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE chio_finding_market_aggregate_events FORCE ROW LEVEL SECURITY;
ALTER TABLE chio_finding_market_aggregate_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE chio_finding_market_aggregate_heads FORCE ROW LEVEL SECURITY;

DO $policy$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'chio_finding_market_aggregate_events'
          AND policyname = 'chio_finding_market_aggregate_events_tenant_isolation'
    ) THEN
        CREATE POLICY chio_finding_market_aggregate_events_tenant_isolation
        ON chio_finding_market_aggregate_events
        USING (tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), ''))
        WITH CHECK (tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), ''));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'chio_finding_market_aggregate_heads'
          AND policyname = 'chio_finding_market_aggregate_heads_tenant_isolation'
    ) THEN
        CREATE POLICY chio_finding_market_aggregate_heads_tenant_isolation
        ON chio_finding_market_aggregate_heads
        USING (tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), ''))
        WITH CHECK (tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), ''));
    END IF;
END
$policy$;
