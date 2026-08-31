CREATE TABLE IF NOT EXISTS chio_finding_market_principals (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    principal_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('buyer', 'seller', 'evaluator', 'auditor', 'operator')),
    capability_public_key_hex TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at BIGINT NOT NULL CHECK (created_at > 0),
    updated_at BIGINT NOT NULL CHECK (updated_at > 0),
    PRIMARY KEY (tenant_id, principal_id),
    UNIQUE (tenant_id, capability_public_key_hex)
);

CREATE TABLE IF NOT EXISTS chio_finding_market_api_keys (
    tenant_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    verifier_sha256 CHAR(64) NOT NULL,
    allowed_actions TEXT[] NOT NULL CHECK (cardinality(allowed_actions) BETWEEN 1 AND 64),
    active_from BIGINT NOT NULL CHECK (active_from > 0),
    expires_at BIGINT NOT NULL CHECK (expires_at > active_from),
    revoked_at BIGINT,
    rotated_from_key_id TEXT,
    created_at BIGINT NOT NULL CHECK (created_at > 0),
    PRIMARY KEY (tenant_id, key_id),
    FOREIGN KEY (tenant_id, principal_id)
        REFERENCES chio_finding_market_principals(tenant_id, principal_id),
    FOREIGN KEY (tenant_id, rotated_from_key_id)
        REFERENCES chio_finding_market_api_keys(tenant_id, key_id),
    CHECK (revoked_at IS NULL OR revoked_at >= active_from)
);

CREATE INDEX IF NOT EXISTS chio_finding_market_api_keys_principal
ON chio_finding_market_api_keys (tenant_id, principal_id, active_from, expires_at);

CREATE TABLE IF NOT EXISTS chio_finding_market_dpop_nonces (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    capability_id TEXT NOT NULL,
    nonce_sha256 CHAR(64) NOT NULL,
    valid_through BIGINT NOT NULL CHECK (valid_through > 0),
    created_at BIGINT NOT NULL CHECK (created_at > 0),
    PRIMARY KEY (tenant_id, capability_id, nonce_sha256)
);

CREATE INDEX IF NOT EXISTS chio_finding_market_dpop_nonces_expiry
ON chio_finding_market_dpop_nonces (tenant_id, valid_through);

CREATE TABLE IF NOT EXISTS chio_finding_market_capability_uses (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    capability_id TEXT NOT NULL,
    used_count BIGINT NOT NULL CHECK (used_count > 0),
    max_invocations BIGINT NOT NULL CHECK (max_invocations > 0),
    expires_at BIGINT NOT NULL CHECK (expires_at > 0),
    updated_at BIGINT NOT NULL CHECK (updated_at > 0),
    PRIMARY KEY (tenant_id, capability_id),
    CHECK (used_count <= max_invocations)
);

CREATE INDEX IF NOT EXISTS chio_finding_market_capability_uses_expiry
ON chio_finding_market_capability_uses (tenant_id, expires_at);

CREATE TABLE IF NOT EXISTS chio_finding_market_security_events (
    tenant_id TEXT NOT NULL REFERENCES chio_finding_market_tenants(tenant_id),
    event_id TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    artifact_sha256 CHAR(64) NOT NULL,
    artifact_json BYTEA NOT NULL,
    created_at BIGINT NOT NULL CHECK (created_at > 0),
    PRIMARY KEY (tenant_id, event_id)
);

DO $rls$
DECLARE
    table_name TEXT;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'chio_finding_market_principals',
        'chio_finding_market_api_keys',
        'chio_finding_market_dpop_nonces',
        'chio_finding_market_capability_uses',
        'chio_finding_market_security_events'
    ]
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        IF NOT EXISTS (
            SELECT 1
            FROM pg_policies
            WHERE schemaname = current_schema()
              AND tablename = table_name
              AND policyname = table_name || '_tenant_isolation'
        ) THEN
            EXECUTE format(
                'CREATE POLICY %I ON %I USING (tenant_id = NULLIF(current_setting(''chio.tenant_id'', TRUE), '''')) WITH CHECK (tenant_id = NULLIF(current_setting(''chio.tenant_id'', TRUE), ''''))',
                table_name || '_tenant_isolation',
                table_name
            );
        END IF;
    END LOOP;
END
$rls$;
