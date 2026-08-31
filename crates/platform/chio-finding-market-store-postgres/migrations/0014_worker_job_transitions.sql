CREATE OR REPLACE FUNCTION chio_finding_market_claim_jobs(
    requested_tenant_id TEXT,
    requested_worker_id TEXT,
    requested_lease_duration_secs BIGINT,
    requested_limit BIGINT
) RETURNS SETOF public.chio_finding_market_jobs
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    configured_limit BIGINT;
    active_leases BIGINT;
    available_slots BIGINT;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
        OR requested_worker_id IS NULL
        OR octet_length(requested_worker_id) NOT BETWEEN 1 AND 256
        OR requested_worker_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        OR requested_lease_duration_secs NOT BETWEEN 1 AND 3600
        OR requested_limit NOT BETWEEN 1 AND 100
    THEN
        RETURN;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(requested_tenant_id, 2));
    SELECT max_concurrent_jobs INTO configured_limit
    FROM public.chio_finding_market_tenants
    WHERE tenant_id = requested_tenant_id AND enabled
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    SELECT COUNT(*) INTO active_leases
    FROM public.chio_finding_market_jobs
    WHERE tenant_id = requested_tenant_id
      AND state = 'leased'
      AND lease_expires_at > floor(extract(epoch from clock_timestamp()))::bigint;
    available_slots := configured_limit - active_leases;
    IF available_slots <= 0 THEN
        RETURN;
    END IF;
    RETURN QUERY
    WITH clock AS (
        SELECT floor(extract(epoch from clock_timestamp()))::bigint AS now_secs
    ), due AS (
        SELECT jobs.tenant_id, jobs.job_id
        FROM public.chio_finding_market_jobs AS jobs CROSS JOIN clock
        WHERE jobs.tenant_id = requested_tenant_id
          AND jobs.available_at <= clock.now_secs
          AND (
              jobs.state IN ('pending', 'failed')
              OR (jobs.state = 'leased' AND jobs.lease_expires_at <= clock.now_secs)
          )
        ORDER BY jobs.available_at, jobs.created_at, jobs.job_id
        FOR UPDATE OF jobs SKIP LOCKED
        LIMIT LEAST(available_slots, requested_limit)
    )
    UPDATE public.chio_finding_market_jobs AS jobs
    SET state = 'leased', lease_owner = requested_worker_id,
        lease_expires_at = clock.now_secs + requested_lease_duration_secs,
        attempt_count = jobs.attempt_count + 1,
        lease_fence = jobs.lease_fence + 1,
        updated_at = clock.now_secs,
        last_error_code = NULL
    FROM due CROSS JOIN clock
    WHERE jobs.tenant_id = due.tenant_id AND jobs.job_id = due.job_id
    RETURNING jobs.*;
END
$function$;

CREATE OR REPLACE FUNCTION chio_finding_market_renew_job_lease(
    requested_tenant_id TEXT,
    requested_job_id TEXT,
    requested_worker_id TEXT,
    requested_lease_fence BIGINT,
    requested_lease_duration_secs BIGINT
) RETURNS BIGINT
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
    WITH enabled_tenant AS MATERIALIZED (
        SELECT 1
        FROM public.chio_finding_market_tenants
        WHERE tenant_id = requested_tenant_id AND enabled
        FOR SHARE
    )
    UPDATE public.chio_finding_market_jobs
    SET lease_expires_at = floor(extract(epoch from clock_timestamp()))::bigint
            + requested_lease_duration_secs,
        updated_at = floor(extract(epoch from clock_timestamp()))::bigint
    WHERE requested_tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), '')
      AND EXISTS (SELECT 1 FROM enabled_tenant)
      AND requested_lease_duration_secs BETWEEN 1 AND 3600
      AND tenant_id = requested_tenant_id AND job_id = requested_job_id
      AND state = 'leased' AND lease_owner = requested_worker_id
      AND lease_fence = requested_lease_fence
      AND lease_expires_at > floor(extract(epoch from clock_timestamp()))::bigint
    RETURNING lease_expires_at
$function$;

CREATE OR REPLACE FUNCTION chio_finding_market_complete_job(
    requested_tenant_id TEXT,
    requested_job_id TEXT,
    requested_worker_id TEXT,
    requested_lease_fence BIGINT,
    requested_result_sha256 TEXT,
    requested_result_json BYTEA
) RETURNS SMALLINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    retained public.chio_finding_market_jobs%ROWTYPE;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
        OR requested_result_sha256 !~ '^[0-9a-f]{64}$'
        OR requested_result_json IS NULL
        OR octet_length(requested_result_json) NOT BETWEEN 1 AND 4194304
        OR requested_result_sha256 <> encode(sha256(requested_result_json), 'hex')
    THEN
        RETURN 4;
    END IF;
    PERFORM 1
    FROM public.chio_finding_market_tenants
    WHERE tenant_id = requested_tenant_id AND enabled
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN 4;
    END IF;
    SELECT * INTO retained
    FROM public.chio_finding_market_jobs
    WHERE tenant_id = requested_tenant_id AND job_id = requested_job_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 3;
    END IF;
    IF retained.state = 'completed' THEN
        IF retained.result_sha256 = requested_result_sha256
            AND retained.result_json = requested_result_json
        THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    IF retained.state <> 'leased'
        OR retained.lease_owner <> requested_worker_id
        OR retained.lease_fence <> requested_lease_fence
        OR retained.lease_expires_at <= floor(extract(epoch from clock_timestamp()))::bigint
    THEN
        RETURN 4;
    END IF;
    UPDATE public.chio_finding_market_jobs
    SET state = 'completed', lease_owner = NULL, lease_expires_at = NULL,
        result_sha256 = requested_result_sha256,
        result_json = requested_result_json,
        updated_at = floor(extract(epoch from clock_timestamp()))::bigint
    WHERE tenant_id = requested_tenant_id AND job_id = requested_job_id
      AND state = 'leased' AND lease_owner = requested_worker_id
      AND lease_fence = requested_lease_fence
      AND lease_expires_at > floor(extract(epoch from clock_timestamp()))::bigint;
    IF NOT FOUND THEN
        RETURN 4;
    END IF;
    RETURN 0;
END
$function$;

CREATE OR REPLACE FUNCTION chio_finding_market_fail_job(
    requested_tenant_id TEXT,
    requested_job_id TEXT,
    requested_worker_id TEXT,
    requested_lease_fence BIGINT,
    requested_error_code TEXT,
    requested_retry_delay_secs BIGINT
) RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
    WITH enabled_tenant AS MATERIALIZED (
        SELECT 1
        FROM public.chio_finding_market_tenants
        WHERE tenant_id = requested_tenant_id AND enabled
        FOR SHARE
    ), changed AS (
        UPDATE public.chio_finding_market_jobs
        SET state = 'failed', lease_owner = NULL, lease_expires_at = NULL,
            last_error_code = requested_error_code,
            available_at = floor(extract(epoch from clock_timestamp()))::bigint
                + requested_retry_delay_secs,
            updated_at = floor(extract(epoch from clock_timestamp()))::bigint
        WHERE requested_tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), '')
          AND EXISTS (SELECT 1 FROM enabled_tenant)
          AND requested_retry_delay_secs BETWEEN 1 AND 3600
          AND requested_error_code ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
          AND tenant_id = requested_tenant_id AND job_id = requested_job_id
          AND state = 'leased' AND lease_owner = requested_worker_id
          AND lease_fence = requested_lease_fence
          AND lease_expires_at > floor(extract(epoch from clock_timestamp()))::bigint
        RETURNING 1
    ) SELECT EXISTS(SELECT 1 FROM changed)
$function$;

CREATE OR REPLACE FUNCTION chio_finding_market_relinquish_job_lease(
    requested_tenant_id TEXT,
    requested_job_id TEXT,
    requested_worker_id TEXT,
    requested_lease_fence BIGINT
) RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
    WITH enabled_tenant AS MATERIALIZED (
        SELECT 1
        FROM public.chio_finding_market_tenants
        WHERE tenant_id = requested_tenant_id AND enabled
        FOR SHARE
    ), changed AS (
        UPDATE public.chio_finding_market_jobs
        SET state = 'pending', lease_owner = NULL, lease_expires_at = NULL,
            attempt_count = attempt_count - 1,
            available_at = floor(extract(epoch from clock_timestamp()))::bigint,
            last_error_code = NULL,
            updated_at = floor(extract(epoch from clock_timestamp()))::bigint
        WHERE requested_tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), '')
          AND EXISTS (SELECT 1 FROM enabled_tenant)
          AND tenant_id = requested_tenant_id AND job_id = requested_job_id
          AND state = 'leased' AND lease_owner = requested_worker_id
          AND lease_fence = requested_lease_fence AND attempt_count > 0
        RETURNING 1
    ) SELECT EXISTS(SELECT 1 FROM changed)
$function$;

CREATE OR REPLACE FUNCTION chio_finding_market_exhaust_job(
    requested_tenant_id TEXT,
    requested_job_id TEXT,
    requested_worker_id TEXT,
    requested_lease_fence BIGINT,
    requested_error_code TEXT
) RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
    WITH enabled_tenant AS MATERIALIZED (
        SELECT 1
        FROM public.chio_finding_market_tenants
        WHERE tenant_id = requested_tenant_id AND enabled
        FOR SHARE
    ), changed AS (
        UPDATE public.chio_finding_market_jobs
        SET state = 'exhausted', lease_owner = NULL, lease_expires_at = NULL,
            last_error_code = requested_error_code,
            updated_at = floor(extract(epoch from clock_timestamp()))::bigint
        WHERE requested_tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), '')
          AND EXISTS (SELECT 1 FROM enabled_tenant)
          AND requested_error_code ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
          AND tenant_id = requested_tenant_id AND job_id = requested_job_id
          AND state = 'leased' AND lease_owner = requested_worker_id
          AND lease_fence = requested_lease_fence
          AND lease_expires_at > floor(extract(epoch from clock_timestamp()))::bigint
        RETURNING 1
    ) SELECT EXISTS(SELECT 1 FROM changed)
$function$;

REVOKE ALL ON FUNCTION chio_finding_market_claim_jobs(TEXT, TEXT, BIGINT, BIGINT) FROM PUBLIC;
REVOKE ALL ON FUNCTION chio_finding_market_renew_job_lease(TEXT, TEXT, TEXT, BIGINT, BIGINT) FROM PUBLIC;
REVOKE ALL ON FUNCTION chio_finding_market_complete_job(TEXT, TEXT, TEXT, BIGINT, TEXT, BYTEA) FROM PUBLIC;
REVOKE ALL ON FUNCTION chio_finding_market_fail_job(TEXT, TEXT, TEXT, BIGINT, TEXT, BIGINT) FROM PUBLIC;
REVOKE ALL ON FUNCTION chio_finding_market_relinquish_job_lease(TEXT, TEXT, TEXT, BIGINT) FROM PUBLIC;
REVOKE ALL ON FUNCTION chio_finding_market_exhaust_job(TEXT, TEXT, TEXT, BIGINT, TEXT) FROM PUBLIC;
