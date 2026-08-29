CREATE OR REPLACE FUNCTION chio_finding_market_reject_immutable_mutation()
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
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'append-only cognition-market row cannot be mutated'
        USING ERRCODE = '55000';
END
$function$;

DROP TABLE chio_finding_market_schema_migrations;

CREATE TABLE chio_finding_market_journal_checkpoints (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    checkpoint_sha256 CHAR(64) NOT NULL,
    aggregate_heads_sha256 CHAR(64) NOT NULL,
    terminal_jobs_sha256 CHAR(64) NOT NULL,
    previous_checkpoint_sha256 CHAR(64),
    migration_version BIGINT NOT NULL CHECK (migration_version > 0),
    configuration_revision TEXT NOT NULL,
    signer_key_hex CHAR(64) NOT NULL,
    checkpoint_envelope_json BYTEA NOT NULL,
    created_at BIGINT NOT NULL CHECK (created_at > 0),
    PRIMARY KEY (tenant_id, checkpoint_sha256),
    CONSTRAINT chio_finding_market_journal_checkpoints_previous_fk
        FOREIGN KEY (tenant_id, previous_checkpoint_sha256)
        REFERENCES chio_finding_market_journal_checkpoints
            (tenant_id, checkpoint_sha256),
    CONSTRAINT chio_finding_market_journal_checkpoints_digest_v1 CHECK (
        checkpoint_sha256 !~ '[^0-9a-f]'
        AND aggregate_heads_sha256 !~ '[^0-9a-f]'
        AND terminal_jobs_sha256 !~ '[^0-9a-f]'
        AND signer_key_hex !~ '[^0-9a-f]'
        AND (
            previous_checkpoint_sha256 IS NULL
            OR previous_checkpoint_sha256 !~ '[^0-9a-f]'
        )
    ),
    CONSTRAINT chio_finding_market_journal_checkpoints_config_v1 CHECK (
        octet_length(configuration_revision) BETWEEN 1 AND 256
        AND configuration_revision !~ '[^A-Za-z0-9_.:/-]'
    ),
    CONSTRAINT chio_finding_market_journal_checkpoints_envelope_size_v1 CHECK (
        octet_length(checkpoint_envelope_json) BETWEEN 1 AND 4194304
    )
);

CREATE TABLE chio_finding_market_journal_checkpoint_members (
    tenant_id TEXT NOT NULL,
    checkpoint_sha256 CHAR(64) NOT NULL,
    member_kind TEXT NOT NULL CHECK (member_kind IN ('aggregate', 'job')),
    member_family TEXT NOT NULL,
    member_id TEXT NOT NULL,
    member_revision BIGINT NOT NULL CHECK (member_revision >= 0),
    member_sha256 CHAR(64) NOT NULL,
    PRIMARY KEY (
        tenant_id, checkpoint_sha256, member_kind, member_family, member_id
    ),
    FOREIGN KEY (tenant_id, checkpoint_sha256)
        REFERENCES chio_finding_market_journal_checkpoints
            (tenant_id, checkpoint_sha256),
    CONSTRAINT chio_finding_market_journal_checkpoint_members_identifier_v1 CHECK (
        octet_length(member_family) BETWEEN 1 AND 96
        AND member_family !~ '[^A-Za-z0-9_.:/-]'
        AND octet_length(member_id) BETWEEN 1 AND 256
        AND member_id !~ '[^A-Za-z0-9_.:/-]'
        AND member_sha256 !~ '[^0-9a-f]'
    )
);

CREATE TABLE chio_finding_market_archive_manifests (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    archive_sha256 CHAR(64) NOT NULL,
    resource_kind TEXT NOT NULL CHECK (resource_kind IN ('aggregate', 'job')),
    resource_family TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    resource_revision BIGINT NOT NULL CHECK (resource_revision >= 0),
    resource_sha256 CHAR(64) NOT NULL,
    covered_checkpoint_sha256 CHAR(64) NOT NULL,
    object_uri TEXT NOT NULL,
    object_sha256 CHAR(64) NOT NULL,
    object_size BIGINT NOT NULL CHECK (object_size > 0),
    configuration_revision TEXT NOT NULL,
    previous_archive_sha256 CHAR(64),
    signer_key_hex CHAR(64) NOT NULL,
    archive_envelope_json BYTEA NOT NULL,
    created_at BIGINT NOT NULL CHECK (created_at > 0),
    PRIMARY KEY (tenant_id, archive_sha256),
    UNIQUE (
        tenant_id, resource_kind, resource_family, resource_id,
        resource_revision, archive_sha256
    ),
    FOREIGN KEY (tenant_id, covered_checkpoint_sha256)
        REFERENCES chio_finding_market_journal_checkpoints
            (tenant_id, checkpoint_sha256),
    FOREIGN KEY (tenant_id, previous_archive_sha256)
        REFERENCES chio_finding_market_archive_manifests
            (tenant_id, archive_sha256),
    CONSTRAINT chio_finding_market_archive_manifests_identifier_v1 CHECK (
        octet_length(resource_family) BETWEEN 1 AND 96
        AND resource_family !~ '[^A-Za-z0-9_.:/-]'
        AND octet_length(resource_id) BETWEEN 1 AND 256
        AND resource_id !~ '[^A-Za-z0-9_.:/-]'
        AND octet_length(configuration_revision) BETWEEN 1 AND 256
        AND configuration_revision !~ '[^A-Za-z0-9_.:/-]'
        AND octet_length(object_uri) BETWEEN 1 AND 2048
    ),
    CONSTRAINT chio_finding_market_archive_manifests_digest_v1 CHECK (
        archive_sha256 !~ '[^0-9a-f]'
        AND resource_sha256 !~ '[^0-9a-f]'
        AND covered_checkpoint_sha256 !~ '[^0-9a-f]'
        AND object_sha256 !~ '[^0-9a-f]'
        AND signer_key_hex !~ '[^0-9a-f]'
        AND (previous_archive_sha256 IS NULL OR previous_archive_sha256 !~ '[^0-9a-f]')
    ),
    CONSTRAINT chio_finding_market_archive_manifests_envelope_size_v1 CHECK (
        octet_length(archive_envelope_json) BETWEEN 1 AND 4194304
    )
);

CREATE TABLE chio_finding_market_legal_hold_events (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    hold_event_sha256 CHAR(64) NOT NULL,
    hold_id TEXT NOT NULL,
    resource_kind TEXT NOT NULL CHECK (resource_kind IN ('aggregate', 'job')),
    resource_family TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('placed', 'released')),
    previous_hold_event_sha256 CHAR(64),
    signer_key_hex CHAR(64) NOT NULL,
    hold_envelope_json BYTEA NOT NULL,
    created_at BIGINT NOT NULL CHECK (created_at > 0),
    PRIMARY KEY (tenant_id, hold_event_sha256),
    UNIQUE (tenant_id, hold_id, hold_event_sha256),
    FOREIGN KEY (tenant_id, previous_hold_event_sha256)
        REFERENCES chio_finding_market_legal_hold_events
            (tenant_id, hold_event_sha256),
    CONSTRAINT chio_finding_market_legal_hold_events_identifier_v1 CHECK (
        octet_length(hold_id) BETWEEN 1 AND 256
        AND hold_id !~ '[^A-Za-z0-9_.:/-]'
        AND octet_length(resource_family) BETWEEN 1 AND 96
        AND resource_family !~ '[^A-Za-z0-9_.:/-]'
        AND octet_length(resource_id) BETWEEN 1 AND 256
        AND resource_id !~ '[^A-Za-z0-9_.:/-]'
    ),
    CONSTRAINT chio_finding_market_legal_hold_events_digest_v1 CHECK (
        hold_event_sha256 !~ '[^0-9a-f]'
        AND signer_key_hex !~ '[^0-9a-f]'
        AND (
            previous_hold_event_sha256 IS NULL
            OR previous_hold_event_sha256 !~ '[^0-9a-f]'
        )
    ),
    CONSTRAINT chio_finding_market_legal_hold_events_envelope_size_v1 CHECK (
        octet_length(hold_envelope_json) BETWEEN 1 AND 4194304
    )
);

CREATE TABLE chio_finding_market_restore_verifications (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    verification_sha256 CHAR(64) NOT NULL,
    archive_sha256 CHAR(64) NOT NULL,
    restored_resource_sha256 CHAR(64) NOT NULL,
    signer_key_hex CHAR(64) NOT NULL,
    verification_envelope_json BYTEA NOT NULL,
    verified_at BIGINT NOT NULL CHECK (verified_at > 0),
    PRIMARY KEY (tenant_id, verification_sha256),
    FOREIGN KEY (tenant_id, archive_sha256)
        REFERENCES chio_finding_market_archive_manifests
            (tenant_id, archive_sha256),
    CONSTRAINT chio_finding_market_restore_verifications_digest_v1 CHECK (
        verification_sha256 !~ '[^0-9a-f]'
        AND archive_sha256 !~ '[^0-9a-f]'
        AND restored_resource_sha256 !~ '[^0-9a-f]'
        AND signer_key_hex !~ '[^0-9a-f]'
    ),
    CONSTRAINT chio_finding_market_restore_verifications_envelope_size_v1 CHECK (
        octet_length(verification_envelope_json) BETWEEN 1 AND 4194304
    )
);

CREATE TABLE chio_finding_market_quota_alerts (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    alert_sha256 CHAR(64) NOT NULL,
    quota_kind TEXT NOT NULL,
    observed_value BIGINT NOT NULL CHECK (observed_value >= 0),
    limit_value BIGINT NOT NULL CHECK (limit_value > 0),
    signer_key_hex CHAR(64) NOT NULL,
    alert_envelope_json BYTEA NOT NULL,
    created_at BIGINT NOT NULL CHECK (created_at > 0),
    PRIMARY KEY (tenant_id, alert_sha256),
    CONSTRAINT chio_finding_market_quota_alerts_kind_v1 CHECK (
        octet_length(quota_kind) BETWEEN 1 AND 96
        AND quota_kind !~ '[^A-Za-z0-9_.:/-]'
    ),
    CONSTRAINT chio_finding_market_quota_alerts_digest_v1 CHECK (
        alert_sha256 !~ '[^0-9a-f]'
        AND signer_key_hex !~ '[^0-9a-f]'
    ),
    CONSTRAINT chio_finding_market_quota_alerts_envelope_size_v1 CHECK (
        octet_length(alert_envelope_json) BETWEEN 1 AND 4194304
    )
);

CREATE TABLE chio_finding_market_gc_receipts (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    receipt_sha256 CHAR(64) NOT NULL,
    archive_sha256 CHAR(64) NOT NULL,
    resource_kind TEXT NOT NULL CHECK (resource_kind IN ('aggregate', 'job')),
    resource_family TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    signer_key_hex CHAR(64) NOT NULL,
    receipt_envelope_json BYTEA NOT NULL,
    completed_at BIGINT NOT NULL CHECK (completed_at > 0),
    PRIMARY KEY (tenant_id, receipt_sha256),
    FOREIGN KEY (tenant_id, archive_sha256)
        REFERENCES chio_finding_market_archive_manifests
            (tenant_id, archive_sha256),
    CONSTRAINT chio_finding_market_gc_receipts_digest_v1 CHECK (
        receipt_sha256 !~ '[^0-9a-f]'
        AND archive_sha256 !~ '[^0-9a-f]'
        AND signer_key_hex !~ '[^0-9a-f]'
    ),
    CONSTRAINT chio_finding_market_gc_receipts_envelope_size_v1 CHECK (
        octet_length(receipt_envelope_json) BETWEEN 1 AND 4194304
    )
);

DO $rls$
DECLARE
    table_name TEXT;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'chio_finding_market_journal_checkpoints',
        'chio_finding_market_journal_checkpoint_members',
        'chio_finding_market_archive_manifests',
        'chio_finding_market_legal_hold_events',
        'chio_finding_market_restore_verifications',
        'chio_finding_market_quota_alerts',
        'chio_finding_market_gc_receipts'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format(
            'CREATE POLICY %I ON %I USING (tenant_id = NULLIF(current_setting(''chio.tenant_id'', TRUE), '''')) WITH CHECK (tenant_id = NULLIF(current_setting(''chio.tenant_id'', TRUE), ''''))',
            table_name || '_tenant_isolation',
            table_name
        );
        EXECUTE format(
            'CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION chio_finding_market_reject_immutable_mutation()',
            table_name || '_immutable',
            table_name
        );
    END LOOP;
END
$rls$;

CREATE OR REPLACE FUNCTION chio_finding_market_gc_retained_resource(
    requested_tenant_id TEXT,
    requested_archive_sha256 TEXT,
    requested_resource_kind TEXT,
    requested_resource_family TEXT,
    requested_resource_id TEXT,
    requested_resource_revision BIGINT,
    requested_resource_sha256 TEXT,
    requested_receipt_sha256 TEXT,
    requested_signer_key_hex TEXT,
    requested_receipt_envelope_json BYTEA,
    requested_completed_at BIGINT
) RETURNS SMALLINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    archive_row public.chio_finding_market_archive_manifests%ROWTYPE;
    removed_count BIGINT;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'tenant context does not match retention request'
            USING ERRCODE = '42501';
    END IF;
    SELECT * INTO archive_row
    FROM public.chio_finding_market_archive_manifests
    WHERE tenant_id = requested_tenant_id
      AND archive_sha256 = requested_archive_sha256
      AND resource_kind = requested_resource_kind
      AND resource_family = requested_resource_family
      AND resource_id = requested_resource_id
      AND resource_revision = requested_resource_revision
      AND resource_sha256 = requested_resource_sha256;
    IF NOT FOUND THEN
        RETURN 2;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM public.chio_finding_market_journal_checkpoint_members
        WHERE tenant_id = requested_tenant_id
          AND checkpoint_sha256 = archive_row.covered_checkpoint_sha256
          AND member_kind = requested_resource_kind
          AND member_family = requested_resource_family
          AND member_id = requested_resource_id
          AND member_revision = archive_row.resource_revision
          AND member_sha256 = archive_row.resource_sha256
    ) THEN
        RETURN 2;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM public.chio_finding_market_restore_verifications
        WHERE tenant_id = requested_tenant_id
          AND archive_sha256 = requested_archive_sha256
          AND restored_resource_sha256 = archive_row.resource_sha256
          AND verified_at <= requested_completed_at
    ) THEN
        RETURN 2;
    END IF;
    IF requested_completed_at < archive_row.created_at THEN
        RETURN 2;
    END IF;
    IF EXISTS (
        SELECT 1
        FROM (
            SELECT DISTINCT ON (hold_id) action, created_at
            FROM public.chio_finding_market_legal_hold_events
            WHERE tenant_id = requested_tenant_id
              AND resource_kind = requested_resource_kind
              AND resource_family = requested_resource_family
              AND resource_id = requested_resource_id
            ORDER BY hold_id, created_at DESC, hold_event_sha256 DESC
        ) AS latest_holds
        WHERE action = 'placed'
    ) THEN
        RETURN 3;
    END IF;
    IF EXISTS (
        SELECT 1
        FROM public.chio_finding_market_legal_hold_events
        WHERE tenant_id = requested_tenant_id
          AND resource_kind = requested_resource_kind
          AND resource_family = requested_resource_family
          AND resource_id = requested_resource_id
          AND created_at > requested_completed_at
    ) THEN
        RETURN 2;
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.chio_finding_market_gc_receipts
        WHERE tenant_id = requested_tenant_id
          AND receipt_sha256 = requested_receipt_sha256
    ) THEN
        RETURN 1;
    END IF;
    IF requested_resource_kind = 'job' THEN
        DELETE FROM public.chio_finding_market_jobs
        WHERE tenant_id = requested_tenant_id
          AND job_kind = requested_resource_family
          AND job_id = requested_resource_id
          AND state IN ('completed', 'exhausted');
        GET DIAGNOSTICS removed_count = ROW_COUNT;
    ELSIF requested_resource_kind = 'aggregate' THEN
        DELETE FROM public.chio_finding_market_aggregate_checkpoints
        WHERE tenant_id = requested_tenant_id
          AND aggregate_kind = requested_resource_family
          AND aggregate_id = requested_resource_id;
        DELETE FROM public.chio_finding_market_aggregate_heads
        WHERE tenant_id = requested_tenant_id
          AND aggregate_kind = requested_resource_family
          AND aggregate_id = requested_resource_id;
        DELETE FROM public.chio_finding_market_aggregate_events
        WHERE tenant_id = requested_tenant_id
          AND aggregate_kind = requested_resource_family
          AND aggregate_id = requested_resource_id;
        GET DIAGNOSTICS removed_count = ROW_COUNT;
    ELSE
        RETURN 2;
    END IF;
    IF removed_count = 0 THEN
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_gc_receipts (
        tenant_id, receipt_sha256, archive_sha256, resource_kind,
        resource_family, resource_id, signer_key_hex,
        receipt_envelope_json, completed_at
    ) VALUES (
        requested_tenant_id, requested_receipt_sha256,
        requested_archive_sha256, requested_resource_kind,
        requested_resource_family, requested_resource_id,
        requested_signer_key_hex, requested_receipt_envelope_json,
        requested_completed_at
    );
    RETURN 0;
END
$function$;

REVOKE ALL ON FUNCTION chio_finding_market_gc_retained_resource(
    TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, TEXT, BYTEA, BIGINT
) FROM PUBLIC;

CREATE FUNCTION chio_finding_market_append_journal_checkpoint(
    requested_tenant_id TEXT,
    requested_checkpoint_sha256 TEXT,
    requested_aggregate_heads_sha256 TEXT,
    requested_terminal_jobs_sha256 TEXT,
    requested_previous_checkpoint_sha256 TEXT,
    requested_migration_version BIGINT,
    requested_configuration_revision TEXT,
    requested_signer_key_hex TEXT,
    requested_checkpoint_envelope_json BYTEA,
    requested_created_at BIGINT,
    requested_members JSONB
) RETURNS SMALLINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    retained_envelope BYTEA;
    inserted_members BIGINT;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
        OR jsonb_typeof(requested_members) <> 'array'
    THEN
        RAISE EXCEPTION 'invalid journal checkpoint request'
            USING ERRCODE = '42501';
    END IF;
    SELECT checkpoint_envelope_json INTO retained_envelope
    FROM public.chio_finding_market_journal_checkpoints
    WHERE tenant_id = requested_tenant_id
      AND checkpoint_sha256 = requested_checkpoint_sha256;
    IF FOUND THEN
        IF retained_envelope = requested_checkpoint_envelope_json THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_journal_checkpoints (
        tenant_id, checkpoint_sha256, aggregate_heads_sha256,
        terminal_jobs_sha256, previous_checkpoint_sha256,
        migration_version, configuration_revision, signer_key_hex,
        checkpoint_envelope_json, created_at
    ) VALUES (
        requested_tenant_id, requested_checkpoint_sha256,
        requested_aggregate_heads_sha256, requested_terminal_jobs_sha256,
        requested_previous_checkpoint_sha256, requested_migration_version,
        requested_configuration_revision, requested_signer_key_hex,
        requested_checkpoint_envelope_json, requested_created_at
    );
    INSERT INTO public.chio_finding_market_journal_checkpoint_members (
        tenant_id, checkpoint_sha256, member_kind, member_family,
        member_id, member_revision, member_sha256
    )
    SELECT requested_tenant_id, requested_checkpoint_sha256,
           member.member_kind, member.member_family, member.member_id,
           member.member_revision, member.member_sha256
    FROM jsonb_to_recordset(requested_members) AS member(
        member_kind TEXT,
        member_family TEXT,
        member_id TEXT,
        member_revision BIGINT,
        member_sha256 TEXT
    );
    GET DIAGNOSTICS inserted_members = ROW_COUNT;
    IF inserted_members <> jsonb_array_length(requested_members) THEN
        RAISE EXCEPTION 'journal checkpoint member count mismatch'
            USING ERRCODE = '22023';
    END IF;
    RETURN 0;
END
$function$;

CREATE FUNCTION chio_finding_market_append_archive_manifest(
    requested_tenant_id TEXT,
    requested_archive_sha256 TEXT,
    requested_resource_kind TEXT,
    requested_resource_family TEXT,
    requested_resource_id TEXT,
    requested_resource_revision BIGINT,
    requested_resource_sha256 TEXT,
    requested_covered_checkpoint_sha256 TEXT,
    requested_object_uri TEXT,
    requested_object_sha256 TEXT,
    requested_object_size BIGINT,
    requested_configuration_revision TEXT,
    requested_previous_archive_sha256 TEXT,
    requested_signer_key_hex TEXT,
    requested_archive_envelope_json BYTEA,
    requested_created_at BIGINT
) RETURNS SMALLINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    retained_envelope BYTEA;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'invalid archive manifest request'
            USING ERRCODE = '42501';
    END IF;
    SELECT archive_envelope_json INTO retained_envelope
    FROM public.chio_finding_market_archive_manifests
    WHERE tenant_id = requested_tenant_id
      AND archive_sha256 = requested_archive_sha256;
    IF FOUND THEN
        IF retained_envelope = requested_archive_envelope_json THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_archive_manifests (
        tenant_id, archive_sha256, resource_kind, resource_family,
        resource_id, resource_revision, resource_sha256,
        covered_checkpoint_sha256, object_uri, object_sha256,
        object_size, configuration_revision, previous_archive_sha256,
        signer_key_hex, archive_envelope_json, created_at
    ) VALUES (
        requested_tenant_id, requested_archive_sha256, requested_resource_kind,
        requested_resource_family, requested_resource_id,
        requested_resource_revision, requested_resource_sha256,
        requested_covered_checkpoint_sha256, requested_object_uri,
        requested_object_sha256, requested_object_size,
        requested_configuration_revision, requested_previous_archive_sha256,
        requested_signer_key_hex, requested_archive_envelope_json,
        requested_created_at
    );
    RETURN 0;
END
$function$;

CREATE FUNCTION chio_finding_market_append_legal_hold_event(
    requested_tenant_id TEXT,
    requested_hold_event_sha256 TEXT,
    requested_hold_id TEXT,
    requested_resource_kind TEXT,
    requested_resource_family TEXT,
    requested_resource_id TEXT,
    requested_action TEXT,
    requested_previous_hold_event_sha256 TEXT,
    requested_signer_key_hex TEXT,
    requested_hold_envelope_json BYTEA,
    requested_created_at BIGINT
) RETURNS SMALLINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    retained_envelope BYTEA;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'invalid legal hold request'
            USING ERRCODE = '42501';
    END IF;
    SELECT hold_envelope_json INTO retained_envelope
    FROM public.chio_finding_market_legal_hold_events
    WHERE tenant_id = requested_tenant_id
      AND hold_event_sha256 = requested_hold_event_sha256;
    IF FOUND THEN
        IF retained_envelope = requested_hold_envelope_json THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_legal_hold_events (
        tenant_id, hold_event_sha256, hold_id, resource_kind,
        resource_family, resource_id, action, previous_hold_event_sha256,
        signer_key_hex, hold_envelope_json, created_at
    ) VALUES (
        requested_tenant_id, requested_hold_event_sha256, requested_hold_id,
        requested_resource_kind, requested_resource_family,
        requested_resource_id, requested_action,
        requested_previous_hold_event_sha256, requested_signer_key_hex,
        requested_hold_envelope_json, requested_created_at
    );
    RETURN 0;
END
$function$;

CREATE FUNCTION chio_finding_market_append_restore_verification(
    requested_tenant_id TEXT,
    requested_verification_sha256 TEXT,
    requested_archive_sha256 TEXT,
    requested_restored_resource_sha256 TEXT,
    requested_signer_key_hex TEXT,
    requested_verification_envelope_json BYTEA,
    requested_verified_at BIGINT
) RETURNS SMALLINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    retained_envelope BYTEA;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'invalid restore verification request'
            USING ERRCODE = '42501';
    END IF;
    SELECT verification_envelope_json INTO retained_envelope
    FROM public.chio_finding_market_restore_verifications
    WHERE tenant_id = requested_tenant_id
      AND verification_sha256 = requested_verification_sha256;
    IF FOUND THEN
        IF retained_envelope = requested_verification_envelope_json THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_restore_verifications (
        tenant_id, verification_sha256, archive_sha256,
        restored_resource_sha256, signer_key_hex,
        verification_envelope_json, verified_at
    ) VALUES (
        requested_tenant_id, requested_verification_sha256,
        requested_archive_sha256, requested_restored_resource_sha256,
        requested_signer_key_hex, requested_verification_envelope_json,
        requested_verified_at
    );
    RETURN 0;
END
$function$;

CREATE FUNCTION chio_finding_market_append_quota_alert(
    requested_tenant_id TEXT,
    requested_alert_sha256 TEXT,
    requested_quota_kind TEXT,
    requested_observed_value BIGINT,
    requested_limit_value BIGINT,
    requested_signer_key_hex TEXT,
    requested_alert_envelope_json BYTEA,
    requested_created_at BIGINT
) RETURNS SMALLINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    retained_envelope BYTEA;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'invalid quota alert request'
            USING ERRCODE = '42501';
    END IF;
    SELECT alert_envelope_json INTO retained_envelope
    FROM public.chio_finding_market_quota_alerts
    WHERE tenant_id = requested_tenant_id
      AND alert_sha256 = requested_alert_sha256;
    IF FOUND THEN
        IF retained_envelope = requested_alert_envelope_json THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_quota_alerts (
        tenant_id, alert_sha256, quota_kind, observed_value,
        limit_value, signer_key_hex, alert_envelope_json, created_at
    ) VALUES (
        requested_tenant_id, requested_alert_sha256, requested_quota_kind,
        requested_observed_value, requested_limit_value,
        requested_signer_key_hex, requested_alert_envelope_json,
        requested_created_at
    );
    RETURN 0;
END
$function$;

REVOKE ALL ON FUNCTION chio_finding_market_append_journal_checkpoint(
    TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, BYTEA, BIGINT, JSONB
) FROM PUBLIC;
REVOKE ALL ON FUNCTION chio_finding_market_append_archive_manifest(
    TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, TEXT, TEXT, BIGINT,
    TEXT, TEXT, TEXT, BYTEA, BIGINT
) FROM PUBLIC;
REVOKE ALL ON FUNCTION chio_finding_market_append_legal_hold_event(
    TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BYTEA, BIGINT
) FROM PUBLIC;
REVOKE ALL ON FUNCTION chio_finding_market_append_restore_verification(
    TEXT, TEXT, TEXT, TEXT, TEXT, BYTEA, BIGINT
) FROM PUBLIC;
REVOKE ALL ON FUNCTION chio_finding_market_append_quota_alert(
    TEXT, TEXT, TEXT, BIGINT, BIGINT, TEXT, BYTEA, BIGINT
) FROM PUBLIC;

REVOKE INSERT, UPDATE, DELETE ON chio_finding_market_journal_checkpoints FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE ON chio_finding_market_journal_checkpoint_members FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE ON chio_finding_market_archive_manifests FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE ON chio_finding_market_legal_hold_events FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE ON chio_finding_market_restore_verifications FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE ON chio_finding_market_quota_alerts FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE ON chio_finding_market_gc_receipts FROM PUBLIC;
