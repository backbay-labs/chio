ALTER TABLE chio_finding_market_aggregate_events
    DROP CONSTRAINT chio_finding_market_aggregate_events_kind_v1,
    ADD CONSTRAINT chio_finding_market_aggregate_events_kind_v2 CHECK (
        aggregate_kind IN (
            'finding', 'recipe', 'profile', 'collateral', 'listing',
            'admission', 'participation', 'purchase', 'reveal', 'delivery',
            'purchase_terminal', 'failed_delivery', 'challenge',
            'challenge_outcome', 'verified_fix', 'retraction', 'liability',
            'appeal', 'penalty', 'enforcement', 'settlement', 'status_epoch',
            'audit_round'
        )
    );

ALTER TABLE chio_finding_market_aggregate_heads
    DROP CONSTRAINT chio_finding_market_aggregate_heads_kind_v1,
    ADD CONSTRAINT chio_finding_market_aggregate_heads_kind_v2 CHECK (
        aggregate_kind IN (
            'finding', 'recipe', 'profile', 'collateral', 'listing',
            'admission', 'participation', 'purchase', 'reveal', 'delivery',
            'purchase_terminal', 'failed_delivery', 'challenge',
            'challenge_outcome', 'verified_fix', 'retraction', 'liability',
            'appeal', 'penalty', 'enforcement', 'settlement', 'status_epoch',
            'audit_round'
        )
    );

ALTER TABLE chio_finding_market_aggregate_checkpoints
    DROP CONSTRAINT chio_finding_market_aggregate_checkpoints_kind_v1,
    ADD CONSTRAINT chio_finding_market_aggregate_checkpoints_kind_v2 CHECK (
        aggregate_kind IN (
            'finding', 'recipe', 'profile', 'collateral', 'listing',
            'admission', 'participation', 'purchase', 'reveal', 'delivery',
            'purchase_terminal', 'failed_delivery', 'challenge',
            'challenge_outcome', 'verified_fix', 'retraction', 'liability',
            'appeal', 'penalty', 'enforcement', 'settlement', 'status_epoch',
            'audit_round'
        )
    );

CREATE TABLE chio_finding_market_domain_event_contracts (
    aggregate_kind TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    artifact_schema TEXT NOT NULL,
    signed_artifact BOOLEAN NOT NULL,
    PRIMARY KEY (aggregate_kind, event_kind, artifact_schema),
    CONSTRAINT chio_finding_market_domain_event_contracts_identifier_v1 CHECK (
        octet_length(aggregate_kind) BETWEEN 1 AND 96
        AND aggregate_kind !~ '[^A-Za-z0-9_.:/-]'
        AND octet_length(event_kind) BETWEEN 1 AND 96
        AND event_kind !~ '[^A-Za-z0-9_.:/-]'
        AND octet_length(artifact_schema) BETWEEN 1 AND 256
        AND artifact_schema !~ '[^A-Za-z0-9_.:/-]'
    )
);

INSERT INTO chio_finding_market_domain_event_contracts (
    aggregate_kind, event_kind, artifact_schema, signed_artifact
) VALUES
    ('finding', 'finding.published', 'chio.finding.v1', TRUE),
    ('recipe', 'recipe.registered', 'chio.finding.replay-recipe-input.v1', FALSE),
    ('profile', 'profile.registered', 'chio.finding.challenge-verifier-profile.v1', TRUE),
    ('collateral', 'collateral.registered', 'chio.finding.bond-backing.v1', TRUE),
    ('listing', 'listing.activated', 'chio.finding.market-terms.v1', TRUE),
    ('admission', 'admission.admitted', 'chio.finding.admission.v1', TRUE),
    ('purchase', 'purchase.authorized', 'chio.finding.purchase-record.v1', TRUE),
    ('delivery', 'delivery.accepted', 'chio.finding.delivery.v1', FALSE),
    ('failed_delivery', 'delivery.failed', 'chio.finding.failed-delivery.v1', TRUE),
    ('challenge', 'challenge.submitted', 'chio.finding.challenge.v1', TRUE),
    ('challenge_outcome', 'challenge.finalized', 'chio.finding.challenge-outcome.v1', TRUE),
    ('appeal', 'appeal.finalized', 'chio.finding.challenge-enforcement.v1', TRUE),
    ('enforcement', 'enforcement.finalized', 'chio.finding.challenge-enforcement.v1', TRUE),
    ('status_epoch', 'status.published', 'chio.finding.status-epoch.v1', TRUE),
    ('audit_round', 'audit.finalized', 'chio.finding.audit-report.v1', TRUE);

CREATE TRIGGER chio_finding_market_domain_event_contracts_immutable
BEFORE UPDATE OR DELETE ON chio_finding_market_domain_event_contracts
FOR EACH ROW EXECUTE FUNCTION chio_finding_market_reject_immutable_mutation();

CREATE TABLE chio_finding_market_domain_projections (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    aggregate_kind TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    event_sha256 CHAR(64) NOT NULL,
    event_kind TEXT NOT NULL,
    artifact_schema TEXT NOT NULL,
    payload_sha256 CHAR(64) NOT NULL,
    payload_json BYTEA NOT NULL,
    updated_at BIGINT NOT NULL CHECK (updated_at > 0),
    PRIMARY KEY (tenant_id, aggregate_kind, aggregate_id),
    CONSTRAINT chio_finding_market_domain_projection_head_v1
        FOREIGN KEY (tenant_id, aggregate_kind, aggregate_id, revision, event_sha256)
        REFERENCES chio_finding_market_aggregate_events
            (tenant_id, aggregate_kind, aggregate_id, revision, event_sha256)
        ON DELETE CASCADE,
    CONSTRAINT chio_finding_market_domain_projection_contract_v1
        FOREIGN KEY (aggregate_kind, event_kind, artifact_schema)
        REFERENCES chio_finding_market_domain_event_contracts
            (aggregate_kind, event_kind, artifact_schema),
    CONSTRAINT chio_finding_market_domain_projections_identifier_v1 CHECK (
        octet_length(aggregate_id) BETWEEN 1 AND 256
        AND aggregate_id !~ '[^A-Za-z0-9_.:/-]'
        AND payload_sha256 !~ '[^0-9a-f]'
        AND octet_length(payload_json) BETWEEN 1 AND 4194304
    )
);

ALTER TABLE chio_finding_market_domain_projections ENABLE ROW LEVEL SECURITY;
ALTER TABLE chio_finding_market_domain_projections FORCE ROW LEVEL SECURITY;
CREATE POLICY chio_finding_market_domain_projections_tenant_isolation
ON chio_finding_market_domain_projections
USING (tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), ''))
WITH CHECK (tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), ''));

CREATE FUNCTION chio_finding_market_guard_domain_projection_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $function$
BEGIN
    IF session_user <> current_user
       AND current_user = pg_get_userbyid((
           SELECT relowner FROM pg_class WHERE oid = TG_RELID
       ))
    THEN
        IF TG_OP = 'UPDATE'
           AND NEW.tenant_id = OLD.tenant_id
           AND NEW.aggregate_kind = OLD.aggregate_kind
           AND NEW.aggregate_id = OLD.aggregate_id
           AND NEW.revision = OLD.revision + 1
           AND NEW.updated_at >= OLD.updated_at
        THEN
            RETURN NEW;
        END IF;
        IF TG_OP = 'DELETE' AND pg_trigger_depth() > 1 THEN
            RETURN OLD;
        END IF;
    END IF;
    RAISE EXCEPTION 'cognition-market domain projection cannot be mutated directly'
        USING ERRCODE = '55000';
END
$function$;

CREATE TRIGGER chio_finding_market_domain_projections_immutable
BEFORE UPDATE OR DELETE ON chio_finding_market_domain_projections
FOR EACH ROW EXECUTE FUNCTION chio_finding_market_guard_domain_projection_mutation();

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
    retained_projection public.chio_finding_market_domain_projections%ROWTYPE;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
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
        requested_tenant_id,
        requested_aggregate_kind,
        requested_aggregate_id,
        expected_revision,
        expected_event_sha256,
        requested_event_id,
        requested_event_kind,
        requested_payload_sha256,
        requested_payload_json,
        requested_event_sha256,
        requested_committed_at
    );
    IF append_outcome = 2 THEN
        RETURN 2;
    END IF;
    requested_revision := expected_revision + 1;
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
    DO UPDATE SET
        revision = EXCLUDED.revision,
        event_sha256 = EXCLUDED.event_sha256,
        event_kind = EXCLUDED.event_kind,
        artifact_schema = EXCLUDED.artifact_schema,
        payload_sha256 = EXCLUDED.payload_sha256,
        payload_json = EXCLUDED.payload_json,
        updated_at = EXCLUDED.updated_at;
    RETURN 0;
END
$function$;

REVOKE ALL ON FUNCTION chio_finding_market_append_domain_event(
    TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT, BYTEA, TEXT, BIGINT
) FROM PUBLIC;

DO $legacy_principals$
BEGIN
    IF EXISTS (SELECT 1 FROM chio_finding_market_principals) THEN
        RAISE EXCEPTION
            'typed market migration requires an empty legacy principal table; archive or cryptographically re-provision principals before retrying'
            USING ERRCODE = '55000';
    END IF;
END
$legacy_principals$;

CREATE TABLE chio_finding_market_principal_events (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    event_sha256 CHAR(64) NOT NULL,
    principal_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (
        operation IN (
            'provision', 'disable', 'role_change', 'key_rotation',
            'emergency_revoke'
        )
    ),
    role TEXT NOT NULL CHECK (
        role IN ('buyer', 'seller', 'evaluator', 'auditor', 'operator')
    ),
    capability_public_key_hex CHAR(64),
    overlap_expires_at BIGINT,
    previous_event_sha256 CHAR(64),
    signer_key_hex CHAR(64) NOT NULL,
    event_envelope_json BYTEA NOT NULL,
    created_at BIGINT NOT NULL CHECK (created_at > 0),
    PRIMARY KEY (tenant_id, event_sha256),
    FOREIGN KEY (tenant_id, previous_event_sha256)
        REFERENCES chio_finding_market_principal_events (tenant_id, event_sha256),
    CONSTRAINT chio_finding_market_principal_events_identifier_v1 CHECK (
        octet_length(principal_id) BETWEEN 1 AND 256
        AND principal_id !~ '[^A-Za-z0-9_.:/-]'
        AND signer_key_hex !~ '[^0-9a-f]'
        AND (
            capability_public_key_hex IS NULL
            OR capability_public_key_hex !~ '[^0-9a-f]'
        )
        AND (
            previous_event_sha256 IS NULL
            OR previous_event_sha256 !~ '[^0-9a-f]'
        )
        AND (overlap_expires_at IS NULL OR overlap_expires_at > created_at)
    ),
    CONSTRAINT chio_finding_market_principal_events_envelope_size_v1 CHECK (
        octet_length(event_envelope_json) BETWEEN 1 AND 1048576
    )
);

ALTER TABLE chio_finding_market_principal_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE chio_finding_market_principal_events FORCE ROW LEVEL SECURITY;
CREATE POLICY chio_finding_market_principal_events_tenant_isolation
ON chio_finding_market_principal_events
USING (tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), ''))
WITH CHECK (tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), ''));
CREATE TRIGGER chio_finding_market_principal_events_immutable
BEFORE UPDATE OR DELETE ON chio_finding_market_principal_events
FOR EACH ROW EXECUTE FUNCTION chio_finding_market_reject_immutable_mutation();

CREATE TABLE chio_finding_market_principal_key_overlaps (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    principal_id TEXT NOT NULL,
    capability_public_key_hex CHAR(64) NOT NULL,
    lifecycle_event_sha256 CHAR(64) NOT NULL,
    valid_through BIGINT NOT NULL CHECK (valid_through > 0),
    PRIMARY KEY (tenant_id, capability_public_key_hex, lifecycle_event_sha256),
    FOREIGN KEY (tenant_id, lifecycle_event_sha256)
        REFERENCES chio_finding_market_principal_events (tenant_id, event_sha256),
    CONSTRAINT chio_finding_market_principal_key_overlaps_identifier_v1 CHECK (
        octet_length(principal_id) BETWEEN 1 AND 256
        AND principal_id !~ '[^A-Za-z0-9_.:/-]'
        AND capability_public_key_hex !~ '[^0-9a-f]'
    )
);

ALTER TABLE chio_finding_market_principal_key_overlaps ENABLE ROW LEVEL SECURITY;
ALTER TABLE chio_finding_market_principal_key_overlaps FORCE ROW LEVEL SECURITY;
CREATE POLICY chio_finding_market_principal_key_overlaps_tenant_isolation
ON chio_finding_market_principal_key_overlaps
USING (tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), ''))
WITH CHECK (tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), ''));
CREATE TRIGGER chio_finding_market_principal_key_overlaps_immutable
BEFORE UPDATE OR DELETE ON chio_finding_market_principal_key_overlaps
FOR EACH ROW EXECUTE FUNCTION chio_finding_market_reject_immutable_mutation();

CREATE FUNCTION chio_finding_market_apply_principal_event_unfenced(
    requested_tenant_id TEXT,
    requested_event_sha256 TEXT,
    requested_principal_id TEXT,
    requested_operation TEXT,
    requested_role TEXT,
    requested_capability_public_key_hex TEXT,
    requested_overlap_expires_at BIGINT,
    requested_previous_event_sha256 TEXT,
    requested_signer_key_hex TEXT,
    requested_event_envelope_json BYTEA,
    requested_created_at BIGINT
) RETURNS SMALLINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    previous_event public.chio_finding_market_principal_events%ROWTYPE;
    existing_event public.chio_finding_market_principal_events%ROWTYPE;
    principal_row public.chio_finding_market_principals%ROWTYPE;
    principal_exists BOOLEAN;
    requested_enabled BOOLEAN;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'tenant context does not match principal event'
            USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'chio.finding.hosted.principal-lifecycle.v1:'
            || requested_tenant_id || ':' || requested_principal_id,
        0
    ));
    SELECT * INTO existing_event
    FROM public.chio_finding_market_principal_events
    WHERE tenant_id = requested_tenant_id
      AND event_sha256 = requested_event_sha256;
    IF FOUND THEN
        IF existing_event.principal_id = requested_principal_id
            AND existing_event.operation = requested_operation
            AND existing_event.role = requested_role
            AND existing_event.capability_public_key_hex IS NOT DISTINCT FROM requested_capability_public_key_hex
            AND existing_event.overlap_expires_at IS NOT DISTINCT FROM requested_overlap_expires_at
            AND existing_event.previous_event_sha256 IS NOT DISTINCT FROM requested_previous_event_sha256
            AND existing_event.signer_key_hex = requested_signer_key_hex
            AND existing_event.event_envelope_json = requested_event_envelope_json
            AND existing_event.created_at = requested_created_at
        THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    SELECT * INTO previous_event
    FROM public.chio_finding_market_principal_events
    WHERE tenant_id = requested_tenant_id
      AND principal_id = requested_principal_id
    ORDER BY created_at DESC, event_sha256 DESC
    LIMIT 1;
    principal_exists := FOUND;
    SELECT * INTO principal_row
    FROM public.chio_finding_market_principals
    WHERE tenant_id = requested_tenant_id
      AND principal_id = requested_principal_id
    FOR UPDATE;
    IF FOUND <> principal_exists THEN
        RETURN 2;
    END IF;
    IF requested_operation = 'provision' THEN
        IF principal_exists OR requested_previous_event_sha256 IS NOT NULL THEN
            RETURN 2;
        END IF;
        requested_enabled := TRUE;
    ELSE
        IF NOT principal_exists
            OR previous_event.event_sha256 IS DISTINCT FROM requested_previous_event_sha256
            OR requested_created_at <= previous_event.created_at
        THEN
            RETURN 2;
        END IF;
        requested_enabled := principal_row.enabled;
    END IF;
    IF requested_operation = 'key_rotation' THEN
        IF NOT principal_row.enabled
            OR requested_role <> principal_row.role
            OR previous_event.capability_public_key_hex IS NULL
            OR requested_capability_public_key_hex IS NULL
            OR principal_row.capability_public_key_hex IS DISTINCT FROM previous_event.capability_public_key_hex
            OR principal_row.capability_public_key_hex = requested_capability_public_key_hex
            OR requested_overlap_expires_at IS NULL
            OR requested_overlap_expires_at <= requested_created_at
            OR requested_overlap_expires_at > requested_created_at + 86400
        THEN
            RETURN 2;
        END IF;
    ELSIF requested_operation = 'role_change' THEN
        IF NOT principal_row.enabled
            OR requested_role = principal_row.role
            OR requested_capability_public_key_hex IS DISTINCT FROM principal_row.capability_public_key_hex
        THEN
            RETURN 2;
        END IF;
    ELSIF requested_operation IN ('disable', 'emergency_revoke') THEN
        IF NOT principal_row.enabled
            OR requested_role <> principal_row.role
            OR requested_capability_public_key_hex IS DISTINCT FROM principal_row.capability_public_key_hex
        THEN
            RETURN 2;
        END IF;
        requested_enabled := FALSE;
    ELSIF requested_overlap_expires_at IS NOT NULL THEN
        RETURN 2;
    END IF;
    IF requested_capability_public_key_hex IS NOT NULL
        AND requested_operation IN ('provision', 'key_rotation')
        AND (
            EXISTS (
                SELECT 1 FROM public.chio_finding_market_principals
                WHERE tenant_id = requested_tenant_id
                  AND capability_public_key_hex = requested_capability_public_key_hex
                  AND principal_id <> requested_principal_id
            )
            OR EXISTS (
                SELECT 1
                FROM public.chio_finding_market_principal_key_overlaps
                WHERE tenant_id = requested_tenant_id
                  AND capability_public_key_hex = requested_capability_public_key_hex
                  AND valid_through >= requested_created_at
            )
        )
    THEN
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_principal_events (
        tenant_id, event_sha256, principal_id, operation, role,
        capability_public_key_hex, overlap_expires_at,
        previous_event_sha256, signer_key_hex,
        event_envelope_json, created_at
    ) VALUES (
        requested_tenant_id, requested_event_sha256,
        requested_principal_id, requested_operation, requested_role,
        requested_capability_public_key_hex, requested_overlap_expires_at,
        requested_previous_event_sha256,
        requested_signer_key_hex, requested_event_envelope_json,
        requested_created_at
    );
    INSERT INTO public.chio_finding_market_principals (
        tenant_id, principal_id, role, capability_public_key_hex,
        enabled, created_at, updated_at
    ) VALUES (
        requested_tenant_id, requested_principal_id, requested_role,
        requested_capability_public_key_hex, requested_enabled,
        requested_created_at, requested_created_at
    )
    ON CONFLICT (tenant_id, principal_id)
    DO UPDATE SET
        role = EXCLUDED.role,
        capability_public_key_hex = EXCLUDED.capability_public_key_hex,
        enabled = EXCLUDED.enabled,
        updated_at = EXCLUDED.updated_at;
    IF requested_operation = 'key_rotation' THEN
        INSERT INTO public.chio_finding_market_principal_key_overlaps (
            tenant_id, principal_id, capability_public_key_hex,
            lifecycle_event_sha256, valid_through
        ) VALUES (
            requested_tenant_id, requested_principal_id,
            previous_event.capability_public_key_hex,
            requested_event_sha256, requested_overlap_expires_at
        );
    END IF;
    IF requested_operation IN ('disable', 'emergency_revoke') THEN
        UPDATE public.chio_finding_market_api_keys
        SET revoked_at = requested_created_at
        WHERE tenant_id = requested_tenant_id
          AND principal_id = requested_principal_id
          AND revoked_at IS NULL;
    END IF;
    RETURN 0;
END
$function$;

REVOKE ALL ON FUNCTION chio_finding_market_apply_principal_event_unfenced(
    TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, BYTEA, BIGINT
) FROM PUBLIC;

REVOKE ALL ON chio_finding_market_domain_event_contracts FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE ON chio_finding_market_domain_projections FROM PUBLIC;
REVOKE UPDATE, DELETE ON chio_finding_market_principal_events FROM PUBLIC;
REVOKE UPDATE, DELETE ON chio_finding_market_principal_key_overlaps FROM PUBLIC;
