ALTER TABLE chio_finding_market_jobs
        DROP CONSTRAINT IF EXISTS chio_finding_market_jobs_state_v1,
        DROP CONSTRAINT IF EXISTS chio_finding_market_jobs_lease_v1,
        DROP CONSTRAINT IF EXISTS chio_finding_market_jobs_result_v1,
        DROP CONSTRAINT IF EXISTS chio_finding_market_jobs_error_v1,
        -- Exact PostgreSQL-generated names retained by pre-ledger pilot
        -- databases created from migration 0001 before constraints were named.
        DROP CONSTRAINT IF EXISTS chio_finding_market_jobs_state_check,
        DROP CONSTRAINT IF EXISTS chio_finding_market_jobs_check,
        DROP CONSTRAINT IF EXISTS chio_finding_market_jobs_check1,
        DROP CONSTRAINT IF EXISTS chio_finding_market_jobs_check2,
        -- Exact v2 names make adoption idempotent for databases previously
        -- initialized by the raw-SQL runner.
        DROP CONSTRAINT IF EXISTS chio_finding_market_jobs_state_v2,
        DROP CONSTRAINT IF EXISTS chio_finding_market_jobs_lease_v2,
        DROP CONSTRAINT IF EXISTS chio_finding_market_jobs_result_v2,
        DROP CONSTRAINT IF EXISTS chio_finding_market_jobs_error_v2,
        ADD CONSTRAINT chio_finding_market_jobs_state_v2
            CHECK (state IN ('pending', 'leased', 'completed', 'failed', 'exhausted')),
        ADD CONSTRAINT chio_finding_market_jobs_lease_v2
            CHECK (
                (state = 'leased' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
                OR
                (state <> 'leased' AND lease_owner IS NULL AND lease_expires_at IS NULL)
            ),
        ADD CONSTRAINT chio_finding_market_jobs_result_v2
            CHECK (
                (state = 'completed' AND result_sha256 IS NOT NULL AND result_json IS NOT NULL)
                OR
                (state <> 'completed' AND result_sha256 IS NULL AND result_json IS NULL)
            ),
        ADD CONSTRAINT chio_finding_market_jobs_error_v2
            CHECK (
                (state IN ('pending', 'completed', 'leased') AND last_error_code IS NULL)
                OR
                (state IN ('failed', 'exhausted') AND last_error_code IS NOT NULL)
            );
