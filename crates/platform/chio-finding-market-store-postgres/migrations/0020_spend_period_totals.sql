-- Per-period spend accumulator. Reservation admission performs one
-- conditional increment against this row instead of summing the tenant's
-- billing-period reservations, and releases return their units.

CREATE TABLE IF NOT EXISTS chio_finding_market_spend_periods (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    billing_period CHAR(7) NOT NULL CHECK (billing_period ~ '^[0-9]{4}-[0-9]{2}$'),
    consumed_units BIGINT NOT NULL DEFAULT 0 CHECK (consumed_units >= 0),
    updated_at BIGINT NOT NULL CHECK (updated_at >= 0),
    PRIMARY KEY (tenant_id, billing_period)
);

INSERT INTO chio_finding_market_spend_periods (tenant_id, billing_period, consumed_units, updated_at)
SELECT
    tenant_id,
    billing_period,
    COALESCE(SUM(units), 0),
    FLOOR(EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::BIGINT
FROM chio_finding_market_spend_reservations
WHERE state IN ('reserved', 'committed')
GROUP BY tenant_id, billing_period
ON CONFLICT (tenant_id, billing_period) DO NOTHING;

DO $rls$
DECLARE
    table_name TEXT;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'chio_finding_market_spend_periods'
    ]
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        IF NOT EXISTS (
            SELECT 1
            FROM pg_policies
            WHERE schemaname = current_schema()
              AND tablename = table_name
              AND policyname = table_name || '_tenant_isolation'
        ) THEN
            EXECUTE format(
                'CREATE POLICY %I ON %I USING (tenant_id = NULLIF(current_setting(''chio.tenant_id'', TRUE), '''')) WITH CHECK (tenant_id = NULLIF(current_setting(''chio.tenant_id'', TRUE), ''''))',
                table_name || '_tenant_isolation',
                table_name
            );
        END IF;
    END LOOP;
END
$rls$;
