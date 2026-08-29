ALTER TABLE chio_finding_market_tenants
    ADD COLUMN IF NOT EXISTS max_concurrent_jobs INTEGER NOT NULL DEFAULT 1
        CHECK (max_concurrent_jobs BETWEEN 1 AND 1024),
    ADD COLUMN IF NOT EXISTS max_queued_jobs BIGINT NOT NULL DEFAULT 1
        CHECK (max_queued_jobs BETWEEN 1 AND 10000000),
    ADD COLUMN IF NOT EXISTS max_monthly_spend_units BIGINT NOT NULL DEFAULT 1
        CHECK (max_monthly_spend_units BETWEEN 1 AND 9007199254740991),
    ADD COLUMN IF NOT EXISTS configuration_revision TEXT NOT NULL DEFAULT 'unconfigured'
        CHECK (length(configuration_revision) BETWEEN 1 AND 256);

CREATE TABLE IF NOT EXISTS chio_finding_market_spend_reservations (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    reservation_id TEXT NOT NULL,
    billing_period CHAR(7) NOT NULL,
    units BIGINT NOT NULL CHECK (units BETWEEN 1 AND 9007199254740991),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'committed', 'released')),
    created_at BIGINT NOT NULL CHECK (created_at > 0),
    updated_at BIGINT NOT NULL CHECK (updated_at > 0),
    PRIMARY KEY (tenant_id, reservation_id)
);

CREATE INDEX IF NOT EXISTS chio_finding_market_spend_period
ON chio_finding_market_spend_reservations (tenant_id, billing_period, state);

ALTER TABLE chio_finding_market_spend_reservations ENABLE ROW LEVEL SECURITY;
ALTER TABLE chio_finding_market_spend_reservations FORCE ROW LEVEL SECURITY;

DO $policy$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'chio_finding_market_spend_reservations'
          AND policyname = 'chio_finding_market_spend_reservations_tenant_isolation'
    ) THEN
        CREATE POLICY chio_finding_market_spend_reservations_tenant_isolation
        ON chio_finding_market_spend_reservations
        USING (
            tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), '')
        )
        WITH CHECK (
            tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), '')
        );
    END IF;
END
$policy$;
