ALTER TABLE chio_finding_market_jobs
    ADD COLUMN IF NOT EXISTS lease_fence BIGINT NOT NULL DEFAULT 0
        CHECK (lease_fence >= 0);

UPDATE chio_finding_market_jobs
SET lease_fence = attempt_count
WHERE state <> 'pending'
  AND lease_fence = 0
  AND attempt_count > 0;

ALTER TABLE chio_finding_market_jobs
    DROP CONSTRAINT IF EXISTS chio_finding_market_jobs_fence_v3,
    ADD CONSTRAINT chio_finding_market_jobs_fence_v3
        CHECK (
            (state = 'pending' AND attempt_count = 0 AND lease_fence = 0)
            OR
            (state <> 'pending' AND attempt_count > 0 AND lease_fence > 0)
        );
