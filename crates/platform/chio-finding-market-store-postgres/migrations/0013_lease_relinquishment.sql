ALTER TABLE chio_finding_market_jobs
    DROP CONSTRAINT IF EXISTS chio_finding_market_jobs_fence_v3,
    ADD CONSTRAINT chio_finding_market_jobs_fence_v13
        CHECK (
            lease_fence >= attempt_count
            AND (
                state = 'pending'
                OR
                (state <> 'pending' AND attempt_count > 0 AND lease_fence > 0)
            )
        );
