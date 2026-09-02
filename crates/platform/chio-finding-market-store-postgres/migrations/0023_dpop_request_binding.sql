-- Durable record of which requests a capability has already admitted.
--
-- A mutation whose write is cut short after admission has already spent its
-- nonce and a slot of its capability budget. The nonce alone cannot carry
-- the recovery: it expires with the proof, which may be seconds. This
-- ledger lives for the capability's lifetime, so an identical retry with a
-- fresh proof is recognised as that request resuming rather than as a new
-- invocation. Only requests carrying an idempotency key are recorded, so a
-- read proof can never be reused this way.

CREATE TABLE IF NOT EXISTS chio_finding_market_capability_request_admissions (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    capability_id TEXT NOT NULL,
    request_sha256 CHAR(64) NOT NULL,
    admitted_at BIGINT NOT NULL CHECK (admitted_at > 0),
    expires_at BIGINT NOT NULL CHECK (expires_at > 0),
    PRIMARY KEY (tenant_id, capability_id, request_sha256),
    CONSTRAINT chio_finding_market_capability_request_digest_v1 CHECK (
        request_sha256 !~ '[^0-9a-f]'
    )
);

CREATE INDEX IF NOT EXISTS chio_finding_market_capability_request_expiry
ON chio_finding_market_capability_request_admissions (tenant_id, expires_at);

DO $rls$
DECLARE
    table_name TEXT;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'chio_finding_market_capability_request_admissions'
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
