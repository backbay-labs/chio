CREATE TABLE IF NOT EXISTS chio_finding_market_tenants (
    tenant_id TEXT PRIMARY KEY,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at BIGINT NOT NULL CHECK (created_at > 0)
);

CREATE TABLE IF NOT EXISTS chio_finding_market_jobs (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    job_id TEXT NOT NULL,
    job_kind TEXT NOT NULL,
    request_sha256 CHAR(64) NOT NULL,
    payload_sha256 CHAR(64) NOT NULL,
    payload_json BYTEA NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'completed', 'failed')),
    attempt_count BIGINT NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    available_at BIGINT NOT NULL CHECK (available_at > 0),
    lease_owner TEXT,
    lease_expires_at BIGINT,
    result_sha256 CHAR(64),
    result_json BYTEA,
    last_error_code TEXT,
    created_at BIGINT NOT NULL CHECK (created_at > 0),
    updated_at BIGINT NOT NULL CHECK (updated_at > 0),
    PRIMARY KEY (tenant_id, job_id),
    CHECK (
        (state = 'leased' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR
        (state <> 'leased' AND lease_owner IS NULL AND lease_expires_at IS NULL)
    ),
    CHECK (
        (state = 'completed' AND result_sha256 IS NOT NULL AND result_json IS NOT NULL)
        OR
        (state <> 'completed' AND result_sha256 IS NULL AND result_json IS NULL)
    ),
    CHECK (
        (state IN ('pending', 'completed') AND last_error_code IS NULL)
        OR state IN ('leased', 'failed')
    )
);

CREATE INDEX IF NOT EXISTS chio_finding_market_jobs_due
ON chio_finding_market_jobs (tenant_id, state, available_at, created_at, job_id);

ALTER TABLE chio_finding_market_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE chio_finding_market_jobs FORCE ROW LEVEL SECURITY;

DO $policy$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'chio_finding_market_jobs'
          AND policyname = 'chio_finding_market_jobs_tenant_isolation'
    ) THEN
        CREATE POLICY chio_finding_market_jobs_tenant_isolation
        ON chio_finding_market_jobs
        USING (
            tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), '')
        )
        WITH CHECK (
            tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), '')
        );
    END IF;
END
$policy$;
