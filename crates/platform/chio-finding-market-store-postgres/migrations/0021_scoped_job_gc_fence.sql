-- Scope the job-insert tombstone fence to the exact job identity so it
-- serializes against the retention garbage collector, which already locks
-- the same derived key, instead of taking a tenant-wide lock that pairs
-- with nothing on the collector side.

CREATE OR REPLACE FUNCTION chio_finding_market_reject_gc_job_resurrection()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
BEGIN
    IF NEW.tenant_id IS NULL
        OR NEW.tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'tenant context does not match job insertion'
            USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'chio.finding.hosted.retention-job-lock.v1:'
                || NEW.tenant_id || ':' || NEW.job_kind || ':' || NEW.job_id,
            0
        )
    );
    IF EXISTS (
        SELECT 1
        FROM public.chio_finding_market_gc_receipts
        WHERE tenant_id = NEW.tenant_id
          AND resource_kind = 'job'
          AND resource_family = NEW.job_kind
          AND resource_id = NEW.job_id
    ) THEN
        RAISE EXCEPTION 'garbage-collected job identity cannot be reused'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'chio_finding_market_jobs_gc_tombstone_v1';
    END IF;
    RETURN NEW;
END
$function$;
