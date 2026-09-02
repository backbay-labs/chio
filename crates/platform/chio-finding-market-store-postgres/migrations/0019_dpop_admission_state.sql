-- Per-tenant DPoP admission accounting. Admission reads this row instead of
-- counting live nonces, and expired-credential sweeps run under capacity
-- pressure or the retention cadence instead of on every request.

CREATE TABLE IF NOT EXISTS chio_finding_market_dpop_admission_state (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    live_nonces BIGINT NOT NULL DEFAULT 0 CHECK (live_nonces >= 0),
    last_swept_at BIGINT NOT NULL DEFAULT 0 CHECK (last_swept_at >= 0),
    PRIMARY KEY (tenant_id)
);

INSERT INTO chio_finding_market_dpop_admission_state (tenant_id, live_nonces, last_swept_at)
SELECT tenant_id, COUNT(*), 0
FROM chio_finding_market_dpop_nonces
GROUP BY tenant_id
ON CONFLICT (tenant_id) DO NOTHING;

DO $rls$
DECLARE
    table_name TEXT;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'chio_finding_market_dpop_admission_state'
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
