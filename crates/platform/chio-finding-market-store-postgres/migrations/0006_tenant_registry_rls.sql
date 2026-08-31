ALTER TABLE chio_finding_market_tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE chio_finding_market_tenants FORCE ROW LEVEL SECURITY;

DO $policy$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'chio_finding_market_tenants'
          AND policyname = 'chio_finding_market_tenants_tenant_isolation'
    ) THEN
        CREATE POLICY chio_finding_market_tenants_tenant_isolation
        ON chio_finding_market_tenants
        USING (
            tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), '')
        )
        WITH CHECK (
            tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), '')
        );
    END IF;
END
$policy$;
