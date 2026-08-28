DO $migration$
DECLARE
    item RECORD;
BEGIN
    FOR item IN
        SELECT conname
        FROM pg_constraint
        WHERE conrelid = 'chio_finding_market_jobs'::regclass
          AND contype = 'c'
          AND pg_get_constraintdef(oid) LIKE '%state%'
    LOOP
        EXECUTE format(
            'ALTER TABLE chio_finding_market_jobs DROP CONSTRAINT %I',
            item.conname
        );
    END LOOP;

    ALTER TABLE chio_finding_market_jobs
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
END
$migration$;
