CREATE TABLE chio_finding_market_authority_state (
    tenant_id TEXT PRIMARY KEY REFERENCES chio_finding_market_tenants(tenant_id),
    authority TEXT NOT NULL CHECK (authority IN ('sqlite', 'postgres')),
    authority_epoch BIGINT NOT NULL CHECK (authority_epoch > 0),
    mode TEXT NOT NULL CHECK (
        mode IN ('shadow', 'frozen', 'rollback_window', 'authoritative', 'retired')
    ),
    mutations_enabled BOOLEAN NOT NULL,
    last_replication_sequence BIGINT NOT NULL CHECK (last_replication_sequence >= 0),
    last_outbox_sequence BIGINT NOT NULL CHECK (last_outbox_sequence >= 0),
    rollback_window_ends_at BIGINT,
    configuration_revision TEXT NOT NULL,
    transition_sha256 CHAR(64),
    updated_at BIGINT NOT NULL CHECK (updated_at > 0),
    CONSTRAINT chio_finding_market_authority_state_consistency_v1 CHECK (
        (authority = 'sqlite' AND mode IN ('shadow', 'frozen'))
        OR (authority = 'postgres' AND mode IN (
            'rollback_window', 'authoritative', 'retired', 'frozen'
        ))
    ),
    CONSTRAINT chio_finding_market_authority_state_revision_v1 CHECK (
        octet_length(configuration_revision) BETWEEN 1 AND 256
        AND configuration_revision !~ '[^A-Za-z0-9_.:/-]'
        AND (transition_sha256 IS NULL OR transition_sha256 !~ '[^0-9a-f]')
    )
);

INSERT INTO chio_finding_market_authority_state (
    tenant_id, authority, authority_epoch, mode, mutations_enabled,
    last_replication_sequence, last_outbox_sequence, rollback_window_ends_at,
    configuration_revision, transition_sha256, updated_at
)
SELECT tenant_id, 'sqlite', 1, 'shadow', TRUE, 0, 0, NULL,
       configuration_revision, NULL, created_at
FROM chio_finding_market_tenants;

CREATE FUNCTION chio_finding_market_initialize_authority_state()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
BEGIN
    INSERT INTO public.chio_finding_market_authority_state (
        tenant_id, authority, authority_epoch, mode, mutations_enabled,
        last_replication_sequence, last_outbox_sequence, rollback_window_ends_at,
        configuration_revision, transition_sha256, updated_at
    ) VALUES (
        NEW.tenant_id, 'sqlite', 1, 'shadow', TRUE, 0, 0, NULL,
        NEW.configuration_revision, NULL, NEW.created_at
    );
    RETURN NEW;
END
$function$;

CREATE TRIGGER chio_finding_market_tenants_initialize_authority_state
AFTER INSERT ON chio_finding_market_tenants
FOR EACH ROW EXECUTE FUNCTION chio_finding_market_initialize_authority_state();

REVOKE ALL ON FUNCTION chio_finding_market_initialize_authority_state()
FROM PUBLIC;

CREATE TABLE chio_finding_market_replication_events (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    replication_event_sha256 CHAR(64) NOT NULL,
    source_authority TEXT NOT NULL CHECK (source_authority IN ('sqlite', 'postgres')),
    authority_epoch BIGINT NOT NULL CHECK (authority_epoch > 0),
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    aggregate_kind TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    artifact_schema TEXT NOT NULL,
    expected_revision BIGINT NOT NULL CHECK (expected_revision >= 0),
    expected_event_sha256 CHAR(64),
    payload_sha256 CHAR(64) NOT NULL,
    payload_json BYTEA NOT NULL,
    signer_key_hex CHAR(64) NOT NULL,
    event_envelope_json BYTEA NOT NULL,
    committed_at BIGINT NOT NULL CHECK (committed_at > 0),
    PRIMARY KEY (tenant_id, replication_event_sha256),
    UNIQUE (tenant_id, source_authority, authority_epoch, sequence),
    UNIQUE (tenant_id, source_authority, authority_epoch, event_id),
    FOREIGN KEY (aggregate_kind, event_kind, artifact_schema)
        REFERENCES chio_finding_market_domain_event_contracts
            (aggregate_kind, event_kind, artifact_schema),
    CONSTRAINT chio_finding_market_replication_events_identifier_v1 CHECK (
        octet_length(aggregate_id) BETWEEN 1 AND 256
        AND aggregate_id !~ '[^A-Za-z0-9_.:/-]'
        AND octet_length(event_id) BETWEEN 1 AND 256
        AND event_id !~ '[^A-Za-z0-9_.:/-]'
        AND payload_sha256 !~ '[^0-9a-f]'
        AND signer_key_hex !~ '[^0-9a-f]'
        AND (
            expected_event_sha256 IS NULL
            OR expected_event_sha256 !~ '[^0-9a-f]'
        )
    ),
    CONSTRAINT chio_finding_market_replication_events_payload_size_v1 CHECK (
        octet_length(payload_json) BETWEEN 1 AND 4194304
        AND octet_length(event_envelope_json) BETWEEN 1 AND 4194304
    )
);

CREATE TABLE chio_finding_market_principal_replication_events (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    replication_event_sha256 CHAR(64) NOT NULL,
    source_authority TEXT NOT NULL CHECK (source_authority IN ('sqlite', 'postgres')),
    authority_epoch BIGINT NOT NULL CHECK (authority_epoch > 0),
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    principal_event_sha256 CHAR(64) NOT NULL,
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
    principal_signer_key_hex CHAR(64) NOT NULL,
    principal_event_envelope_json BYTEA NOT NULL,
    source_signer_key_hex CHAR(64) NOT NULL,
    replication_event_envelope_json BYTEA NOT NULL,
    committed_at BIGINT NOT NULL CHECK (committed_at > 0),
    PRIMARY KEY (tenant_id, replication_event_sha256),
    UNIQUE (tenant_id, source_authority, authority_epoch, sequence),
    UNIQUE (tenant_id, source_authority, authority_epoch, principal_event_sha256),
    CONSTRAINT chio_finding_market_principal_replication_events_identifier_v1 CHECK (
        octet_length(principal_id) BETWEEN 1 AND 256
        AND principal_id !~ '[^A-Za-z0-9_.:/-]'
        AND replication_event_sha256 !~ '[^0-9a-f]'
        AND principal_event_sha256 !~ '[^0-9a-f]'
        AND principal_signer_key_hex !~ '[^0-9a-f]'
        AND source_signer_key_hex !~ '[^0-9a-f]'
        AND (
            capability_public_key_hex IS NULL
            OR capability_public_key_hex !~ '[^0-9a-f]'
        )
        AND (
            previous_event_sha256 IS NULL
            OR previous_event_sha256 !~ '[^0-9a-f]'
        )
        AND (overlap_expires_at IS NULL OR overlap_expires_at > committed_at)
    ),
    CONSTRAINT chio_finding_market_principal_replication_events_envelope_size_v1 CHECK (
        octet_length(principal_event_envelope_json) BETWEEN 1 AND 1048576
        AND octet_length(replication_event_envelope_json) BETWEEN 1 AND 4194304
    )
);

CREATE TABLE chio_finding_market_replication_checks (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    check_sha256 CHAR(64) NOT NULL,
    source_authority TEXT NOT NULL CHECK (source_authority IN ('sqlite', 'postgres')),
    authority_epoch BIGINT NOT NULL CHECK (authority_epoch > 0),
    through_sequence BIGINT NOT NULL CHECK (through_sequence >= 0),
    source_projection_sha256 CHAR(64) NOT NULL,
    target_projection_sha256 CHAR(64) NOT NULL,
    lag_seconds BIGINT NOT NULL CHECK (lag_seconds >= 0),
    projection_difference_count BIGINT NOT NULL CHECK (projection_difference_count >= 0),
    security_counter_count BIGINT NOT NULL CHECK (security_counter_count >= 0),
    signer_key_hex CHAR(64) NOT NULL,
    check_envelope_json BYTEA NOT NULL,
    checked_at BIGINT NOT NULL CHECK (checked_at > 0),
    PRIMARY KEY (tenant_id, check_sha256),
    CONSTRAINT chio_finding_market_replication_checks_digest_v1 CHECK (
        check_sha256 !~ '[^0-9a-f]'
        AND source_projection_sha256 !~ '[^0-9a-f]'
        AND target_projection_sha256 !~ '[^0-9a-f]'
        AND signer_key_hex !~ '[^0-9a-f]'
    ),
    CONSTRAINT chio_finding_market_replication_checks_envelope_size_v1 CHECK (
        octet_length(check_envelope_json) BETWEEN 1 AND 4194304
    )
);

CREATE TABLE chio_finding_market_replication_outbox (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    authority_epoch BIGINT NOT NULL CHECK (authority_epoch > 0),
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    aggregate_kind TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    expected_revision BIGINT NOT NULL CHECK (expected_revision >= 0),
    expected_event_sha256 CHAR(64),
    event_id TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    artifact_schema TEXT NOT NULL,
    payload_sha256 CHAR(64) NOT NULL,
    payload_json BYTEA NOT NULL,
    event_sha256 CHAR(64) NOT NULL,
    committed_at BIGINT NOT NULL CHECK (committed_at > 0),
    PRIMARY KEY (tenant_id, authority_epoch, sequence),
    UNIQUE (tenant_id, authority_epoch, event_id),
    FOREIGN KEY (aggregate_kind, event_kind, artifact_schema)
        REFERENCES chio_finding_market_domain_event_contracts
            (aggregate_kind, event_kind, artifact_schema),
    CONSTRAINT chio_finding_market_replication_outbox_identifier_v1 CHECK (
        octet_length(aggregate_id) BETWEEN 1 AND 256
        AND aggregate_id !~ '[^A-Za-z0-9_.:/-]'
        AND octet_length(event_id) BETWEEN 1 AND 256
        AND event_id !~ '[^A-Za-z0-9_.:/-]'
        AND payload_sha256 !~ '[^0-9a-f]'
        AND event_sha256 !~ '[^0-9a-f]'
        AND (expected_event_sha256 IS NULL OR expected_event_sha256 !~ '[^0-9a-f]')
        AND octet_length(payload_json) BETWEEN 1 AND 4194304
    )
);

CREATE TABLE chio_finding_market_principal_replication_outbox (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    authority_epoch BIGINT NOT NULL CHECK (authority_epoch > 0),
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    principal_event_sha256 CHAR(64) NOT NULL,
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
    committed_at BIGINT NOT NULL CHECK (committed_at > 0),
    PRIMARY KEY (tenant_id, authority_epoch, sequence),
    UNIQUE (tenant_id, authority_epoch, principal_event_sha256),
    CONSTRAINT chio_finding_market_principal_replication_outbox_identifier_v1 CHECK (
        octet_length(principal_id) BETWEEN 1 AND 256
        AND principal_id !~ '[^A-Za-z0-9_.:/-]'
        AND principal_event_sha256 !~ '[^0-9a-f]'
        AND signer_key_hex !~ '[^0-9a-f]'
        AND (
            capability_public_key_hex IS NULL
            OR capability_public_key_hex !~ '[^0-9a-f]'
        )
        AND (
            previous_event_sha256 IS NULL
            OR previous_event_sha256 !~ '[^0-9a-f]'
        )
        AND (overlap_expires_at IS NULL OR overlap_expires_at > committed_at)
        AND octet_length(event_envelope_json) BETWEEN 1 AND 1048576
    )
);

CREATE TABLE chio_finding_market_authority_transitions (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    transition_sha256 CHAR(64) NOT NULL,
    operation TEXT NOT NULL CHECK (
        operation IN ('freeze', 'cutover', 'rollback', 'retire_sqlite')
    ),
    from_authority TEXT NOT NULL CHECK (from_authority IN ('sqlite', 'postgres')),
    to_authority TEXT NOT NULL CHECK (to_authority IN ('sqlite', 'postgres')),
    from_epoch BIGINT NOT NULL CHECK (from_epoch > 0),
    to_epoch BIGINT NOT NULL CHECK (to_epoch > 0),
    through_sequence BIGINT NOT NULL CHECK (through_sequence >= 0),
    source_checkpoint_sha256 CHAR(64) NOT NULL,
    target_checkpoint_sha256 CHAR(64) NOT NULL,
    configuration_revision TEXT NOT NULL,
    rollback_window_ends_at BIGINT,
    signer_key_hex CHAR(64) NOT NULL,
    transition_envelope_json BYTEA NOT NULL,
    created_at BIGINT NOT NULL CHECK (created_at > 0),
    PRIMARY KEY (tenant_id, transition_sha256),
    CONSTRAINT chio_finding_market_authority_transitions_digest_v1 CHECK (
        transition_sha256 !~ '[^0-9a-f]'
        AND source_checkpoint_sha256 !~ '[^0-9a-f]'
        AND target_checkpoint_sha256 !~ '[^0-9a-f]'
        AND signer_key_hex !~ '[^0-9a-f]'
    ),
    CONSTRAINT chio_finding_market_authority_transitions_epoch_v1 CHECK (
        to_epoch = from_epoch + 1
        AND octet_length(configuration_revision) BETWEEN 1 AND 256
        AND configuration_revision !~ '[^A-Za-z0-9_.:/-]'
    ),
    CONSTRAINT chio_finding_market_authority_transitions_envelope_size_v1 CHECK (
        octet_length(transition_envelope_json) BETWEEN 1 AND 4194304
    )
);

DO $rls$
DECLARE
    table_name TEXT;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'chio_finding_market_authority_state',
        'chio_finding_market_replication_events',
        'chio_finding_market_principal_replication_events',
        'chio_finding_market_replication_checks',
        'chio_finding_market_replication_outbox',
        'chio_finding_market_principal_replication_outbox',
        'chio_finding_market_authority_transitions'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format(
            'CREATE POLICY %I ON %I USING (tenant_id = NULLIF(current_setting(''chio.tenant_id'', TRUE), '''')) WITH CHECK (tenant_id = NULLIF(current_setting(''chio.tenant_id'', TRUE), ''''))',
            table_name || '_tenant_isolation',
            table_name
        );
    END LOOP;
END
$rls$;

CREATE TRIGGER chio_finding_market_replication_events_immutable
BEFORE UPDATE OR DELETE ON chio_finding_market_replication_events
FOR EACH ROW EXECUTE FUNCTION chio_finding_market_reject_immutable_mutation();
CREATE TRIGGER chio_finding_market_principal_replication_events_immutable
BEFORE UPDATE OR DELETE ON chio_finding_market_principal_replication_events
FOR EACH ROW EXECUTE FUNCTION chio_finding_market_reject_immutable_mutation();
CREATE TRIGGER chio_finding_market_replication_checks_immutable
BEFORE UPDATE OR DELETE ON chio_finding_market_replication_checks
FOR EACH ROW EXECUTE FUNCTION chio_finding_market_reject_immutable_mutation();
CREATE TRIGGER chio_finding_market_replication_outbox_immutable
BEFORE UPDATE OR DELETE ON chio_finding_market_replication_outbox
FOR EACH ROW EXECUTE FUNCTION chio_finding_market_reject_immutable_mutation();
CREATE TRIGGER chio_finding_market_principal_replication_outbox_immutable
BEFORE UPDATE OR DELETE ON chio_finding_market_principal_replication_outbox
FOR EACH ROW EXECUTE FUNCTION chio_finding_market_reject_immutable_mutation();
CREATE TRIGGER chio_finding_market_authority_transitions_immutable
BEFORE UPDATE OR DELETE ON chio_finding_market_authority_transitions
FOR EACH ROW EXECUTE FUNCTION chio_finding_market_reject_immutable_mutation();

CREATE FUNCTION chio_finding_market_append_replication_check(
    requested_tenant_id TEXT,
    requested_check_sha256 TEXT,
    requested_source_authority TEXT,
    requested_authority_epoch BIGINT,
    requested_through_sequence BIGINT,
    requested_source_projection_sha256 TEXT,
    requested_target_projection_sha256 TEXT,
    requested_lag_seconds BIGINT,
    requested_projection_difference_count BIGINT,
    requested_security_counter_count BIGINT,
    requested_signer_key_hex TEXT,
    requested_check_envelope_json BYTEA,
    requested_checked_at BIGINT
) RETURNS SMALLINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    authority_row public.chio_finding_market_authority_state%ROWTYPE;
    retained_envelope BYTEA;
    previous_checked_at BIGINT;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'tenant context does not match replication check'
            USING ERRCODE = '42501';
    END IF;
    SELECT * INTO authority_row
    FROM public.chio_finding_market_authority_state
    WHERE tenant_id = requested_tenant_id
    FOR SHARE;
    IF NOT FOUND
        OR authority_row.authority_epoch <> requested_authority_epoch
        OR requested_source_authority NOT IN ('sqlite', 'postgres')
        OR authority_row.authority <> requested_source_authority
        OR (CASE requested_source_authority
            WHEN 'sqlite' THEN authority_row.last_replication_sequence
            ELSE authority_row.last_outbox_sequence
           END) <> requested_through_sequence
        OR requested_checked_at > floor(extract(epoch from clock_timestamp()))::bigint + 30
        OR requested_checked_at < floor(extract(epoch from clock_timestamp()))::bigint - 30
    THEN
        RETURN 2;
    END IF;
    SELECT check_envelope_json INTO retained_envelope
    FROM public.chio_finding_market_replication_checks
    WHERE tenant_id = requested_tenant_id
      AND check_sha256 = requested_check_sha256;
    IF FOUND THEN
        IF retained_envelope = requested_check_envelope_json THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    SELECT MAX(checked_at) INTO previous_checked_at
    FROM public.chio_finding_market_replication_checks
    WHERE tenant_id = requested_tenant_id
      AND authority_epoch = requested_authority_epoch
      AND source_authority = requested_source_authority;
    IF previous_checked_at IS NOT NULL
        AND requested_checked_at < previous_checked_at
    THEN
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_replication_checks (
        tenant_id, check_sha256, source_authority, authority_epoch,
        through_sequence, source_projection_sha256,
        target_projection_sha256, lag_seconds,
        projection_difference_count, security_counter_count,
        signer_key_hex, check_envelope_json, checked_at
    ) VALUES (
        requested_tenant_id, requested_check_sha256,
        requested_source_authority, requested_authority_epoch,
        requested_through_sequence, requested_source_projection_sha256,
        requested_target_projection_sha256, requested_lag_seconds,
        requested_projection_difference_count, requested_security_counter_count,
        requested_signer_key_hex, requested_check_envelope_json,
        requested_checked_at
    );
    RETURN 0;
END
$function$;

CREATE FUNCTION chio_finding_market_apply_principal_event(
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
    authority_row public.chio_finding_market_authority_state%ROWTYPE;
    principal_event public.chio_finding_market_principal_events%ROWTYPE;
    lifecycle_outcome SMALLINT;
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
        OR requested_created_at > floor(extract(epoch from clock_timestamp()))::bigint + 30
        OR requested_created_at < floor(extract(epoch from clock_timestamp()))::bigint - 30
        OR NOT EXISTS (
            SELECT 1
            FROM (
                SELECT replication_check.*
                FROM public.chio_finding_market_replication_checks AS replication_check
                WHERE replication_check.tenant_id = requested_tenant_id
                  AND replication_check.authority_epoch = authority_row.authority_epoch
                  AND replication_check.source_authority = 'postgres'
                ORDER BY replication_check.through_sequence DESC,
                         replication_check.checked_at DESC,
                         replication_check.check_sha256 DESC
                LIMIT 1
            ) AS replication_check
            WHERE replication_check.source_projection_sha256 = replication_check.target_projection_sha256
              AND replication_check.through_sequence = authority_row.last_outbox_sequence
              AND replication_check.lag_seconds <= 30
              AND replication_check.checked_at <= floor(extract(epoch from clock_timestamp()))::bigint + 30
              AND replication_check.checked_at >= floor(extract(epoch from clock_timestamp()))::bigint - 30
              AND replication_check.projection_difference_count = 0
              AND replication_check.security_counter_count = 0
        )
    THEN
        RETURN 2;
    END IF;
    lifecycle_outcome := public.chio_finding_market_apply_principal_event_unfenced(
        requested_tenant_id, requested_event_sha256, requested_principal_id,
        requested_operation, requested_role, requested_capability_public_key_hex,
        requested_overlap_expires_at, requested_previous_event_sha256,
        requested_signer_key_hex, requested_event_envelope_json,
        requested_created_at
    );
    IF lifecycle_outcome <> 0 OR authority_row.mode <> 'rollback_window' THEN
        RETURN lifecycle_outcome;
    END IF;
    SELECT * INTO principal_event
    FROM public.chio_finding_market_principal_events
    WHERE tenant_id = requested_tenant_id
      AND event_sha256 = requested_event_sha256;
    IF NOT FOUND THEN
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_principal_replication_outbox (
        tenant_id, authority_epoch, sequence, principal_event_sha256,
        principal_id, operation, role, capability_public_key_hex,
        overlap_expires_at, previous_event_sha256, signer_key_hex,
        event_envelope_json, committed_at
    ) VALUES (
        requested_tenant_id, authority_row.authority_epoch,
        authority_row.last_outbox_sequence + 1, principal_event.event_sha256,
        principal_event.principal_id, principal_event.operation,
        principal_event.role, principal_event.capability_public_key_hex,
        principal_event.overlap_expires_at, principal_event.previous_event_sha256,
        principal_event.signer_key_hex, principal_event.event_envelope_json,
        requested_created_at
    );
    UPDATE public.chio_finding_market_authority_state
    SET last_outbox_sequence = last_outbox_sequence + 1,
        updated_at = requested_created_at
    WHERE tenant_id = requested_tenant_id;
    RETURN 0;
END
$function$;

CREATE FUNCTION chio_finding_market_apply_principal_replication_event(
    requested_tenant_id TEXT,
    requested_replication_event_sha256 TEXT,
    requested_source_authority TEXT,
    requested_authority_epoch BIGINT,
    requested_sequence BIGINT,
    requested_principal_event_sha256 TEXT,
    requested_principal_id TEXT,
    requested_operation TEXT,
    requested_role TEXT,
    requested_capability_public_key_hex TEXT,
    requested_overlap_expires_at BIGINT,
    requested_previous_event_sha256 TEXT,
    requested_principal_signer_key_hex TEXT,
    requested_principal_event_envelope_json BYTEA,
    requested_source_signer_key_hex TEXT,
    requested_replication_event_envelope_json BYTEA,
    requested_committed_at BIGINT
) RETURNS SMALLINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    authority_row public.chio_finding_market_authority_state%ROWTYPE;
    existing_event public.chio_finding_market_principal_replication_events%ROWTYPE;
    lifecycle_outcome SMALLINT;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'tenant context does not match principal replication event'
            USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'chio.finding.hosted.replication.v1:' || requested_tenant_id,
        0
    ));
    SELECT * INTO authority_row
    FROM public.chio_finding_market_authority_state
    WHERE tenant_id = requested_tenant_id
    FOR UPDATE;
    IF NOT FOUND
        OR authority_row.authority <> 'sqlite'
        OR authority_row.mode NOT IN ('shadow', 'frozen')
        OR authority_row.authority_epoch <> requested_authority_epoch
        OR requested_source_authority <> 'sqlite'
        OR requested_committed_at > floor(extract(epoch from clock_timestamp()))::bigint + 30
    THEN
        RETURN 2;
    END IF;
    SELECT * INTO existing_event
    FROM public.chio_finding_market_principal_replication_events
    WHERE tenant_id = requested_tenant_id
      AND replication_event_sha256 = requested_replication_event_sha256;
    IF FOUND THEN
        IF existing_event.replication_event_envelope_json = requested_replication_event_envelope_json
            AND existing_event.principal_event_envelope_json = requested_principal_event_envelope_json
        THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    IF requested_sequence <> authority_row.last_replication_sequence + 1
        OR EXISTS (
            SELECT 1
            FROM public.chio_finding_market_principal_replication_events
            WHERE tenant_id = requested_tenant_id
              AND principal_event_sha256 = requested_principal_event_sha256
        )
    THEN
        RETURN 2;
    END IF;
    lifecycle_outcome := public.chio_finding_market_apply_principal_event_unfenced(
        requested_tenant_id, requested_principal_event_sha256,
        requested_principal_id, requested_operation, requested_role,
        requested_capability_public_key_hex, requested_overlap_expires_at,
        requested_previous_event_sha256, requested_principal_signer_key_hex,
        requested_principal_event_envelope_json, requested_committed_at
    );
    IF lifecycle_outcome <> 0 THEN
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_principal_replication_events (
        tenant_id, replication_event_sha256, source_authority,
        authority_epoch, sequence, principal_event_sha256, principal_id,
        operation, role, capability_public_key_hex, overlap_expires_at,
        previous_event_sha256, principal_signer_key_hex,
        principal_event_envelope_json, source_signer_key_hex,
        replication_event_envelope_json, committed_at
    ) VALUES (
        requested_tenant_id, requested_replication_event_sha256,
        requested_source_authority, requested_authority_epoch,
        requested_sequence, requested_principal_event_sha256,
        requested_principal_id, requested_operation, requested_role,
        requested_capability_public_key_hex, requested_overlap_expires_at,
        requested_previous_event_sha256, requested_principal_signer_key_hex,
        requested_principal_event_envelope_json, requested_source_signer_key_hex,
        requested_replication_event_envelope_json, requested_committed_at
    );
    UPDATE public.chio_finding_market_authority_state
    SET last_replication_sequence = requested_sequence,
        updated_at = requested_committed_at
    WHERE tenant_id = requested_tenant_id;
    RETURN 0;
END
$function$;

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
              AND replication_check.through_sequence = authority_row.last_outbox_sequence
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

CREATE OR REPLACE FUNCTION chio_finding_market_apply_replication_event(
    requested_tenant_id TEXT,
    requested_replication_event_sha256 TEXT,
    requested_source_authority TEXT,
    requested_authority_epoch BIGINT,
    requested_sequence BIGINT,
    requested_aggregate_kind TEXT,
    requested_aggregate_id TEXT,
    requested_expected_revision BIGINT,
    requested_expected_event_sha256 TEXT,
    requested_event_id TEXT,
    requested_event_kind TEXT,
    requested_artifact_schema TEXT,
    requested_payload_sha256 TEXT,
    requested_payload_json BYTEA,
    requested_event_sha256 TEXT,
    requested_signer_key_hex TEXT,
    requested_event_envelope_json BYTEA,
    requested_committed_at BIGINT
) RETURNS SMALLINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    authority_row public.chio_finding_market_authority_state%ROWTYPE;
    existing_event public.chio_finding_market_replication_events%ROWTYPE;
    append_outcome SMALLINT;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'tenant context does not match replication event'
            USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'chio.finding.hosted.replication.v1:' || requested_tenant_id,
        0
    ));
    SELECT * INTO authority_row
    FROM public.chio_finding_market_authority_state
    WHERE tenant_id = requested_tenant_id
    FOR UPDATE;
    IF NOT FOUND
        OR authority_row.authority <> 'sqlite'
        OR authority_row.mode NOT IN ('shadow', 'frozen')
        OR authority_row.authority_epoch <> requested_authority_epoch
        OR requested_source_authority <> 'sqlite'
        OR requested_committed_at > floor(extract(epoch from clock_timestamp()))::bigint + 30
    THEN
        RETURN 2;
    END IF;
    SELECT * INTO existing_event
    FROM public.chio_finding_market_replication_events
    WHERE tenant_id = requested_tenant_id
      AND replication_event_sha256 = requested_replication_event_sha256;
    IF FOUND THEN
        IF existing_event.event_envelope_json = requested_event_envelope_json THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    IF requested_sequence <> authority_row.last_replication_sequence + 1
        OR NOT EXISTS (
            SELECT 1 FROM public.chio_finding_market_domain_event_contracts
            WHERE aggregate_kind = requested_aggregate_kind
              AND event_kind = requested_event_kind
              AND artifact_schema = requested_artifact_schema
        )
    THEN
        RETURN 2;
    END IF;
    append_outcome := public.chio_finding_market_append_aggregate_event(
        requested_tenant_id, requested_aggregate_kind,
        requested_aggregate_id, requested_expected_revision,
        requested_expected_event_sha256, requested_event_id,
        requested_event_kind, requested_payload_sha256,
        requested_payload_json, requested_event_sha256,
        requested_committed_at
    );
    IF append_outcome = 2 THEN
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_domain_projections (
        tenant_id, aggregate_kind, aggregate_id, revision, event_sha256,
        event_kind, artifact_schema, payload_sha256, payload_json, updated_at
    ) VALUES (
        requested_tenant_id, requested_aggregate_kind,
        requested_aggregate_id, requested_expected_revision + 1,
        requested_event_sha256, requested_event_kind,
        requested_artifact_schema, requested_payload_sha256,
        requested_payload_json, requested_committed_at
    )
    ON CONFLICT (tenant_id, aggregate_kind, aggregate_id)
    DO UPDATE SET revision = EXCLUDED.revision,
                  event_sha256 = EXCLUDED.event_sha256,
                  event_kind = EXCLUDED.event_kind,
                  artifact_schema = EXCLUDED.artifact_schema,
                  payload_sha256 = EXCLUDED.payload_sha256,
                  payload_json = EXCLUDED.payload_json,
                  updated_at = EXCLUDED.updated_at;
    INSERT INTO public.chio_finding_market_replication_events (
        tenant_id, replication_event_sha256, source_authority,
        authority_epoch, sequence, aggregate_kind, aggregate_id,
        event_id, event_kind, artifact_schema, expected_revision,
        expected_event_sha256, payload_sha256, payload_json,
        signer_key_hex, event_envelope_json, committed_at
    ) VALUES (
        requested_tenant_id, requested_replication_event_sha256,
        requested_source_authority, requested_authority_epoch,
        requested_sequence, requested_aggregate_kind,
        requested_aggregate_id, requested_event_id,
        requested_event_kind, requested_artifact_schema,
        requested_expected_revision, requested_expected_event_sha256,
        requested_payload_sha256, requested_payload_json,
        requested_signer_key_hex, requested_event_envelope_json,
        requested_committed_at
    );
    UPDATE public.chio_finding_market_authority_state
    SET last_replication_sequence = requested_sequence,
        updated_at = requested_committed_at
    WHERE tenant_id = requested_tenant_id;
    RETURN append_outcome;
END
$function$;

CREATE OR REPLACE FUNCTION chio_finding_market_apply_authority_transition(
    requested_tenant_id TEXT,
    requested_transition_sha256 TEXT,
    requested_operation TEXT,
    requested_from_authority TEXT,
    requested_to_authority TEXT,
    requested_from_epoch BIGINT,
    requested_to_epoch BIGINT,
    requested_through_sequence BIGINT,
    requested_source_checkpoint_sha256 TEXT,
    requested_target_checkpoint_sha256 TEXT,
    requested_configuration_revision TEXT,
    requested_rollback_window_ends_at BIGINT,
    requested_signer_key_hex TEXT,
    requested_transition_envelope_json BYTEA,
    requested_created_at BIGINT
) RETURNS SMALLINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    authority_row public.chio_finding_market_authority_state%ROWTYPE;
    latest_check public.chio_finding_market_replication_checks%ROWTYPE;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'tenant context does not match authority transition'
            USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'chio.finding.hosted.authority.v1:' || requested_tenant_id,
        0
    ));
    IF EXISTS (
        SELECT 1 FROM public.chio_finding_market_authority_transitions
        WHERE tenant_id = requested_tenant_id
          AND transition_sha256 = requested_transition_sha256
          AND transition_envelope_json = requested_transition_envelope_json
    ) THEN
        RETURN 1;
    END IF;
    SELECT * INTO authority_row
    FROM public.chio_finding_market_authority_state
    WHERE tenant_id = requested_tenant_id
    FOR UPDATE;
    IF NOT FOUND
        OR authority_row.authority <> requested_from_authority
        OR authority_row.authority_epoch <> requested_from_epoch
        OR requested_to_epoch <> requested_from_epoch + 1
        OR authority_row.configuration_revision <> requested_configuration_revision
        OR (CASE requested_from_authority
            WHEN 'sqlite' THEN authority_row.last_replication_sequence
            WHEN 'postgres' THEN authority_row.last_outbox_sequence
            ELSE -1
           END) <> requested_through_sequence
    THEN
        RETURN 2;
    END IF;
    SELECT * INTO latest_check
    FROM public.chio_finding_market_replication_checks
    WHERE tenant_id = requested_tenant_id
      AND authority_epoch = requested_from_epoch
      AND source_authority = requested_from_authority
    ORDER BY through_sequence DESC, checked_at DESC, check_sha256 DESC
    LIMIT 1;
    IF NOT FOUND
        OR latest_check.through_sequence <> requested_through_sequence
        OR latest_check.source_projection_sha256 <> latest_check.target_projection_sha256
        OR latest_check.target_projection_sha256 <> requested_target_checkpoint_sha256
        OR latest_check.lag_seconds <> 0
        OR latest_check.checked_at > floor(extract(epoch from clock_timestamp()))::bigint + 30
        OR latest_check.checked_at < floor(extract(epoch from clock_timestamp()))::bigint - 30
        OR latest_check.projection_difference_count <> 0
        OR latest_check.security_counter_count <> 0
        OR requested_source_checkpoint_sha256 <> requested_target_checkpoint_sha256
        OR requested_created_at < latest_check.checked_at
        OR requested_created_at > floor(extract(epoch from clock_timestamp()))::bigint + 30
        OR requested_created_at < floor(extract(epoch from clock_timestamp()))::bigint - 30
    THEN
        RETURN 2;
    END IF;
    IF requested_operation = 'freeze' THEN
        IF requested_from_authority <> requested_to_authority
            OR authority_row.mode NOT IN ('shadow', 'rollback_window', 'authoritative')
            OR requested_rollback_window_ends_at IS NOT NULL
        THEN RETURN 2; END IF;
        UPDATE public.chio_finding_market_authority_state
        SET authority_epoch = requested_to_epoch, mode = 'frozen',
            mutations_enabled = FALSE, transition_sha256 = requested_transition_sha256,
            updated_at = requested_created_at
        WHERE tenant_id = requested_tenant_id;
    ELSIF requested_operation = 'cutover' THEN
        IF requested_from_authority <> 'sqlite'
            OR requested_to_authority <> 'postgres'
            OR authority_row.mode <> 'frozen'
            OR requested_rollback_window_ends_at <> requested_created_at + 604800
        THEN RETURN 2; END IF;
        UPDATE public.chio_finding_market_authority_state
        SET authority = 'postgres', authority_epoch = requested_to_epoch,
            mode = 'rollback_window', mutations_enabled = TRUE,
            rollback_window_ends_at = requested_rollback_window_ends_at,
            transition_sha256 = requested_transition_sha256,
            updated_at = requested_created_at
        WHERE tenant_id = requested_tenant_id;
    ELSIF requested_operation = 'rollback' THEN
        IF requested_from_authority <> 'postgres'
            OR requested_to_authority <> 'sqlite'
            OR authority_row.mode <> 'frozen'
            OR authority_row.rollback_window_ends_at IS NULL
            OR requested_created_at > authority_row.rollback_window_ends_at
            OR requested_rollback_window_ends_at IS NOT NULL
        THEN RETURN 2; END IF;
        UPDATE public.chio_finding_market_authority_state
        SET authority = 'sqlite', authority_epoch = requested_to_epoch,
            mode = 'shadow', mutations_enabled = TRUE,
            rollback_window_ends_at = NULL,
            transition_sha256 = requested_transition_sha256,
            updated_at = requested_created_at
        WHERE tenant_id = requested_tenant_id;
    ELSIF requested_operation = 'retire_sqlite' THEN
        IF requested_from_authority <> 'postgres'
            OR requested_to_authority <> 'postgres'
            OR authority_row.mode <> 'rollback_window'
            OR authority_row.rollback_window_ends_at IS NULL
            OR clock_timestamp() < to_timestamp(authority_row.rollback_window_ends_at)
            OR requested_rollback_window_ends_at IS NOT NULL
        THEN RETURN 2; END IF;
        UPDATE public.chio_finding_market_authority_state
        SET authority_epoch = requested_to_epoch, mode = 'retired',
            mutations_enabled = TRUE, transition_sha256 = requested_transition_sha256,
            updated_at = requested_created_at
        WHERE tenant_id = requested_tenant_id;
    ELSE
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_authority_transitions (
        tenant_id, transition_sha256, operation, from_authority,
        to_authority, from_epoch, to_epoch, through_sequence,
        source_checkpoint_sha256, target_checkpoint_sha256,
        configuration_revision, rollback_window_ends_at, signer_key_hex,
        transition_envelope_json, created_at
    ) VALUES (
        requested_tenant_id, requested_transition_sha256,
        requested_operation, requested_from_authority,
        requested_to_authority, requested_from_epoch, requested_to_epoch,
        requested_through_sequence, requested_source_checkpoint_sha256,
        requested_target_checkpoint_sha256, requested_configuration_revision,
        requested_rollback_window_ends_at, requested_signer_key_hex,
        requested_transition_envelope_json, requested_created_at
    );
    RETURN 0;
END
$function$;

REVOKE ALL ON FUNCTION chio_finding_market_apply_replication_event(
    TEXT, TEXT, TEXT, BIGINT, BIGINT, TEXT, TEXT, BIGINT, TEXT, TEXT,
    TEXT, TEXT, TEXT, BYTEA, TEXT, TEXT, BYTEA, BIGINT
) FROM PUBLIC;
REVOKE ALL ON FUNCTION chio_finding_market_apply_principal_event(
    TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, BYTEA, BIGINT
) FROM PUBLIC;
REVOKE ALL ON FUNCTION chio_finding_market_apply_principal_replication_event(
    TEXT, TEXT, TEXT, BIGINT, BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT,
    BIGINT, TEXT, TEXT, BYTEA, TEXT, BYTEA, BIGINT
) FROM PUBLIC;
REVOKE ALL ON FUNCTION chio_finding_market_append_replication_check(
    TEXT, TEXT, TEXT, BIGINT, BIGINT, TEXT, TEXT, BIGINT, BIGINT, BIGINT,
    TEXT, BYTEA, BIGINT
) FROM PUBLIC;
REVOKE ALL ON FUNCTION chio_finding_market_apply_authority_transition(
    TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, BIGINT, BIGINT, TEXT, TEXT,
    TEXT, BIGINT, TEXT, BYTEA, BIGINT
) FROM PUBLIC;
REVOKE UPDATE, DELETE ON chio_finding_market_authority_state FROM PUBLIC;
REVOKE UPDATE, DELETE ON chio_finding_market_replication_events FROM PUBLIC;
REVOKE UPDATE, DELETE ON chio_finding_market_principal_replication_events FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE ON chio_finding_market_replication_checks FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE ON chio_finding_market_replication_outbox FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE ON chio_finding_market_principal_replication_outbox FROM PUBLIC;
REVOKE UPDATE, DELETE ON chio_finding_market_authority_transitions FROM PUBLIC;
