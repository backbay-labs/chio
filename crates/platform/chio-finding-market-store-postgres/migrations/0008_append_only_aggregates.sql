ALTER TABLE chio_finding_market_aggregate_events
    ADD CONSTRAINT chio_finding_market_aggregate_events_kind_v1 CHECK (
        aggregate_kind IN (
            'finding', 'listing', 'admission', 'purchase',
            'purchase_terminal', 'failed_delivery', 'challenge',
            'challenge_outcome', 'liability', 'appeal', 'penalty',
            'enforcement', 'settlement', 'status_epoch', 'audit_round'
        )
    ),
    ADD CONSTRAINT chio_finding_market_aggregate_events_identifier_v1 CHECK (
        octet_length(aggregate_id) BETWEEN 1 AND 256
        AND aggregate_id !~ '[^A-Za-z0-9_.:/-]'
        AND octet_length(event_id) BETWEEN 1 AND 256
        AND event_id !~ '[^A-Za-z0-9_.:/-]'
        AND octet_length(event_kind) BETWEEN 1 AND 96
        AND event_kind !~ '[^A-Za-z0-9_.:/-]'
    ),
    ADD CONSTRAINT chio_finding_market_aggregate_events_digest_v1 CHECK (
        payload_sha256 !~ '[^0-9a-f]'
        AND event_sha256 !~ '[^0-9a-f]'
        AND (
            previous_event_sha256 IS NULL
            OR previous_event_sha256 !~ '[^0-9a-f]'
        )
    ),
    ADD CONSTRAINT chio_finding_market_aggregate_events_payload_size_v1 CHECK (
        octet_length(payload_json) BETWEEN 1 AND 4194304
    );

ALTER TABLE chio_finding_market_aggregate_heads
    ADD CONSTRAINT chio_finding_market_aggregate_heads_kind_v1 CHECK (
        aggregate_kind IN (
            'finding', 'listing', 'admission', 'purchase',
            'purchase_terminal', 'failed_delivery', 'challenge',
            'challenge_outcome', 'liability', 'appeal', 'penalty',
            'enforcement', 'settlement', 'status_epoch', 'audit_round'
        )
    ),
    ADD CONSTRAINT chio_finding_market_aggregate_heads_identifier_v1 CHECK (
        octet_length(aggregate_id) BETWEEN 1 AND 256
        AND aggregate_id !~ '[^A-Za-z0-9_.:/-]'
    ),
    ADD CONSTRAINT chio_finding_market_aggregate_heads_digest_v1 CHECK (
        event_sha256 !~ '[^0-9a-f]'
    );

CREATE OR REPLACE FUNCTION chio_finding_market_append_aggregate_event(
    requested_tenant_id TEXT,
    requested_aggregate_kind TEXT,
    requested_aggregate_id TEXT,
    expected_revision BIGINT,
    expected_event_sha256 TEXT,
    requested_event_id TEXT,
    requested_event_kind TEXT,
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
    existing_event public.chio_finding_market_aggregate_events%ROWTYPE;
    existing_head public.chio_finding_market_aggregate_heads%ROWTYPE;
    requested_revision BIGINT;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'tenant context does not match append request'
            USING ERRCODE = '42501';
    END IF;
    IF expected_revision < 0
        OR (expected_revision = 0 AND expected_event_sha256 IS NOT NULL)
        OR (expected_revision > 0 AND expected_event_sha256 IS NULL)
    THEN
        RETURN 2;
    END IF;
    requested_revision := expected_revision + 1;

    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'chio.finding.hosted.aggregate-event-id.v1:'
                || requested_tenant_id || ':' || requested_event_id,
            0
        )
    );
    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'chio.finding.hosted.aggregate-lock.v1:'
                || requested_tenant_id || ':' || requested_aggregate_kind
                || ':' || requested_aggregate_id,
            0
        )
    );
    IF EXISTS (
        SELECT 1
        FROM public.chio_finding_market_gc_receipts
        WHERE tenant_id = requested_tenant_id
          AND resource_kind = 'aggregate'
          AND resource_family = requested_aggregate_kind
          AND resource_id = requested_aggregate_id
    ) THEN
        RETURN 2;
    END IF;

    SELECT * INTO existing_event
    FROM public.chio_finding_market_aggregate_events
    WHERE tenant_id = requested_tenant_id
      AND event_id = requested_event_id
    FOR UPDATE;
    IF FOUND THEN
        IF existing_event.aggregate_kind = requested_aggregate_kind
            AND existing_event.aggregate_id = requested_aggregate_id
            AND existing_event.revision = requested_revision
            AND existing_event.event_kind = requested_event_kind
            AND existing_event.previous_event_sha256 IS NOT DISTINCT FROM expected_event_sha256
            AND existing_event.payload_sha256 = requested_payload_sha256
            AND existing_event.payload_json = requested_payload_json
            AND existing_event.event_sha256 = requested_event_sha256
            AND existing_event.committed_at = requested_committed_at
        THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;

    SELECT * INTO existing_head
    FROM public.chio_finding_market_aggregate_heads
    WHERE tenant_id = requested_tenant_id
      AND aggregate_kind = requested_aggregate_kind
      AND aggregate_id = requested_aggregate_id
    FOR UPDATE;
    IF FOUND THEN
        IF existing_head.revision <> expected_revision
            OR existing_head.event_sha256 IS DISTINCT FROM expected_event_sha256
        THEN
            RETURN 2;
        END IF;
    ELSIF expected_revision <> 0 THEN
        RETURN 2;
    END IF;

    INSERT INTO public.chio_finding_market_aggregate_events (
        tenant_id, aggregate_kind, aggregate_id, revision, event_id,
        event_kind, previous_event_sha256, payload_sha256, payload_json,
        event_sha256, committed_at
    ) VALUES (
        requested_tenant_id, requested_aggregate_kind, requested_aggregate_id,
        requested_revision, requested_event_id, requested_event_kind,
        expected_event_sha256, requested_payload_sha256, requested_payload_json,
        requested_event_sha256, requested_committed_at
    );
    INSERT INTO public.chio_finding_market_aggregate_heads (
        tenant_id, aggregate_kind, aggregate_id, revision, event_sha256, updated_at
    ) VALUES (
        requested_tenant_id, requested_aggregate_kind, requested_aggregate_id,
        requested_revision, requested_event_sha256, requested_committed_at
    )
    ON CONFLICT (tenant_id, aggregate_kind, aggregate_id)
    DO UPDATE SET revision = EXCLUDED.revision,
                  event_sha256 = EXCLUDED.event_sha256,
                  updated_at = EXCLUDED.updated_at;
    RETURN 0;
END
$function$;

REVOKE ALL ON FUNCTION chio_finding_market_append_aggregate_event(
    TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, TEXT, TEXT, BYTEA, TEXT, BIGINT
) FROM PUBLIC;

CREATE OR REPLACE FUNCTION chio_finding_market_reject_immutable_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $function$
BEGIN
    RAISE EXCEPTION 'append-only cognition-market row cannot be mutated'
        USING ERRCODE = '55000';
END
$function$;

DROP TRIGGER IF EXISTS chio_finding_market_aggregate_events_immutable
    ON chio_finding_market_aggregate_events;
CREATE TRIGGER chio_finding_market_aggregate_events_immutable
BEFORE UPDATE OR DELETE ON chio_finding_market_aggregate_events
FOR EACH ROW EXECUTE FUNCTION chio_finding_market_reject_immutable_mutation();

DROP TRIGGER IF EXISTS chio_finding_market_security_events_immutable
    ON chio_finding_market_security_events;
CREATE TRIGGER chio_finding_market_security_events_immutable
BEFORE UPDATE OR DELETE ON chio_finding_market_security_events
FOR EACH ROW EXECUTE FUNCTION chio_finding_market_reject_immutable_mutation();

DROP TRIGGER IF EXISTS chio_finding_market_schema_migrations_immutable
    ON chio_finding_market_schema_migrations;
CREATE TRIGGER chio_finding_market_schema_migrations_immutable
BEFORE UPDATE OR DELETE ON chio_finding_market_schema_migrations
FOR EACH ROW EXECUTE FUNCTION chio_finding_market_reject_immutable_mutation();

REVOKE UPDATE, DELETE ON chio_finding_market_aggregate_events FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE ON chio_finding_market_aggregate_heads FROM PUBLIC;
REVOKE UPDATE, DELETE ON chio_finding_market_security_events FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE ON chio_finding_market_schema_migrations FROM PUBLIC;
