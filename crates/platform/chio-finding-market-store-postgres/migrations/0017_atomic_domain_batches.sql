-- Preserve one freshness admission across an atomic multi-event transaction.
-- Every current-transaction outbox row was admitted by this same function;
-- counting only those rows prevents an earlier transaction from extending the gate.
CREATE OR REPLACE FUNCTION chio_finding_market_append_domain_event(
    requested_tenant_id TEXT,
    requested_aggregate_kind TEXT,
    requested_aggregate_id TEXT,
    expected_revision BIGINT,
    expected_event_sha256 TEXT,
    requested_event_id TEXT,
    requested_event_kind TEXT,
    requested_artifact_schema TEXT,
    requested_payload_sha256 TEXT,
    requested_payload_json BYTEA,
    requested_event_sha256 TEXT,
    requested_committed_at BIGINT
) RETURNS SMALLINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    append_outcome SMALLINT;
    requested_revision BIGINT;
    retained_event public.chio_finding_market_aggregate_events%ROWTYPE;
    retained_projection public.chio_finding_market_domain_projections%ROWTYPE;
    authority_row public.chio_finding_market_authority_state%ROWTYPE;
BEGIN
    SELECT * INTO authority_row
    FROM public.chio_finding_market_authority_state
    WHERE tenant_id = requested_tenant_id
    FOR UPDATE;
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
        OR NOT FOUND
        OR authority_row.authority <> 'postgres'
        OR authority_row.mutations_enabled <> TRUE
        OR authority_row.mode NOT IN ('rollback_window', 'authoritative', 'retired')
    THEN
        RETURN 2;
    END IF;
    requested_revision := expected_revision + 1;
    SELECT * INTO retained_event
    FROM public.chio_finding_market_aggregate_events
    WHERE tenant_id = requested_tenant_id
      AND event_id = requested_event_id;
    IF FOUND THEN
        SELECT * INTO retained_projection
        FROM public.chio_finding_market_domain_projections
        WHERE tenant_id = requested_tenant_id
          AND aggregate_kind = requested_aggregate_kind
          AND aggregate_id = requested_aggregate_id;
        IF retained_event.aggregate_kind = requested_aggregate_kind
            AND retained_event.aggregate_id = requested_aggregate_id
            AND retained_event.revision = requested_revision
            AND retained_event.event_kind = requested_event_kind
            AND retained_event.previous_event_sha256 IS NOT DISTINCT FROM expected_event_sha256
            AND retained_event.payload_sha256 = requested_payload_sha256
            AND retained_event.payload_json = requested_payload_json
            AND retained_event.event_sha256 = requested_event_sha256
            AND retained_event.committed_at = requested_committed_at
            AND FOUND
            AND retained_projection.revision = requested_revision
            AND retained_projection.event_sha256 = requested_event_sha256
            AND retained_projection.event_kind = requested_event_kind
            AND retained_projection.artifact_schema = requested_artifact_schema
            AND retained_projection.payload_sha256 = requested_payload_sha256
            AND retained_projection.payload_json = requested_payload_json
        THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    IF requested_committed_at > floor(extract(epoch from clock_timestamp()))::bigint + 30
        OR requested_committed_at < floor(extract(epoch from clock_timestamp()))::bigint - 30
        OR NOT EXISTS (
            SELECT 1
            FROM (
                SELECT replication_check.*
                FROM public.chio_finding_market_replication_checks AS replication_check
                JOIN public.chio_finding_market_authority_state AS authority_state
                  ON authority_state.tenant_id = replication_check.tenant_id
                 AND authority_state.authority_epoch = replication_check.authority_epoch
                WHERE replication_check.tenant_id = requested_tenant_id
                ORDER BY replication_check.through_sequence DESC,
                         replication_check.checked_at DESC,
                         replication_check.check_sha256 DESC
                LIMIT 1
            ) AS replication_check
            WHERE replication_check.source_projection_sha256 = replication_check.target_projection_sha256
              AND replication_check.source_authority = 'postgres'
              AND replication_check.through_sequence
                  + (
                      SELECT COUNT(*)
                      FROM public.chio_finding_market_replication_outbox AS current_batch
                      WHERE current_batch.tenant_id = requested_tenant_id
                        AND current_batch.xmin = pg_current_xact_id()::xid
                  ) = authority_row.last_outbox_sequence
              AND replication_check.lag_seconds <= 30
              AND replication_check.checked_at <= floor(extract(epoch from clock_timestamp()))::bigint + 30
              AND replication_check.checked_at >= floor(extract(epoch from clock_timestamp()))::bigint - 30
              AND replication_check.projection_difference_count = 0
              AND replication_check.security_counter_count = 0
        )
        OR NOT EXISTS (
            SELECT 1
            FROM public.chio_finding_market_domain_event_contracts
            WHERE aggregate_kind = requested_aggregate_kind
              AND event_kind = requested_event_kind
              AND artifact_schema = requested_artifact_schema
        )
    THEN
        RETURN 2;
    END IF;
    append_outcome := public.chio_finding_market_append_aggregate_event(
        requested_tenant_id, requested_aggregate_kind,
        requested_aggregate_id, expected_revision,
        expected_event_sha256, requested_event_id, requested_event_kind,
        requested_payload_sha256, requested_payload_json,
        requested_event_sha256, requested_committed_at
    );
    IF append_outcome = 2 THEN
        RETURN 2;
    END IF;
    IF append_outcome = 1 THEN
        SELECT * INTO retained_projection
        FROM public.chio_finding_market_domain_projections
        WHERE tenant_id = requested_tenant_id
          AND aggregate_kind = requested_aggregate_kind
          AND aggregate_id = requested_aggregate_id;
        IF NOT FOUND
            OR retained_projection.revision <> requested_revision
            OR retained_projection.event_sha256 <> requested_event_sha256
            OR retained_projection.event_kind <> requested_event_kind
            OR retained_projection.artifact_schema <> requested_artifact_schema
            OR retained_projection.payload_sha256 <> requested_payload_sha256
            OR retained_projection.payload_json <> requested_payload_json
        THEN
            RETURN 2;
        END IF;
        RETURN 1;
    END IF;
    INSERT INTO public.chio_finding_market_domain_projections (
        tenant_id, aggregate_kind, aggregate_id, revision, event_sha256,
        event_kind, artifact_schema, payload_sha256, payload_json, updated_at
    ) VALUES (
        requested_tenant_id, requested_aggregate_kind,
        requested_aggregate_id, requested_revision, requested_event_sha256,
        requested_event_kind, requested_artifact_schema,
        requested_payload_sha256, requested_payload_json,
        requested_committed_at
    )
    ON CONFLICT (tenant_id, aggregate_kind, aggregate_id)
    DO UPDATE SET revision = EXCLUDED.revision,
                  event_sha256 = EXCLUDED.event_sha256,
                  event_kind = EXCLUDED.event_kind,
                  artifact_schema = EXCLUDED.artifact_schema,
                  payload_sha256 = EXCLUDED.payload_sha256,
                  payload_json = EXCLUDED.payload_json,
                  updated_at = EXCLUDED.updated_at;
    IF authority_row.mode = 'rollback_window' THEN
        INSERT INTO public.chio_finding_market_replication_outbox (
            tenant_id, authority_epoch, sequence, aggregate_kind,
            aggregate_id, expected_revision, expected_event_sha256,
            event_id, event_kind, artifact_schema, payload_sha256,
            payload_json, event_sha256, committed_at
        ) VALUES (
            requested_tenant_id, authority_row.authority_epoch,
            authority_row.last_outbox_sequence + 1,
            requested_aggregate_kind, requested_aggregate_id,
            expected_revision, expected_event_sha256, requested_event_id,
            requested_event_kind, requested_artifact_schema,
            requested_payload_sha256, requested_payload_json,
            requested_event_sha256, requested_committed_at
        );
        UPDATE public.chio_finding_market_authority_state
        SET last_outbox_sequence = last_outbox_sequence + 1,
            updated_at = requested_committed_at
        WHERE tenant_id = requested_tenant_id;
    END IF;
    RETURN 0;
END
$function$;
