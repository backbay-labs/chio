use std::collections::BTreeSet;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::{canonical_json_bytes, sha256_hex};
use chio_finding::{
    compute_finding_id, sign_finding, Finding, FindingDescriptor, FindingEvidenceClass,
    FindingGuaranteeClass, FindingOutcomeClass, FINDING_SCHEMA_V1,
};
use chio_finding_market_store_postgres::{
    HostedAggregateCheckpointBody, HostedAggregateKind, HostedArchiveManifestBody,
    HostedAuthorityTransitionBody, HostedAuthorityTransitionOperation, HostedGcReceiptBody,
    HostedJobState, HostedJobWriteOutcome, HostedJournalCheckpointBody, HostedLegalHoldAction,
    HostedLegalHoldBody, HostedMarketAuthority, HostedMarketDomainArtifact,
    HostedMarketDomainEvent, HostedMarketDomainEventKind, HostedMarketStoreError,
    HostedPrincipalLifecycleBody, HostedPrincipalLifecycleOperation,
    HostedPrincipalReplicationEventBody, HostedPrincipalRole, HostedReplicationCheckBody,
    HostedReplicationEventBody, HostedRestoreVerificationBody, HostedRetentionResourceKind,
    HostedRetentionTarget, HostedRollbackOutboxEntry, HostedTenantId, HostedTenantLimits,
    PostgresFindingMarketMigrator, PostgresFindingMarketReplicator, PostgresFindingMarketRetention,
    PostgresFindingMarketStore, HOSTED_AGGREGATE_CHECKPOINT_SCHEMA, HOSTED_ARCHIVE_MANIFEST_SCHEMA,
    HOSTED_AUTHORITY_TRANSITION_SCHEMA, HOSTED_GC_RECEIPT_SCHEMA, HOSTED_JOURNAL_CHECKPOINT_SCHEMA,
    HOSTED_LEGAL_HOLD_SCHEMA, HOSTED_PRINCIPAL_LIFECYCLE_SCHEMA,
    HOSTED_PRINCIPAL_REPLICATION_EVENT_SCHEMA, HOSTED_REPLICATION_CHECK_SCHEMA,
    HOSTED_REPLICATION_EVENT_SCHEMA, HOSTED_RESTORE_VERIFICATION_SCHEMA,
};
use sqlx::Row as _;

#[tokio::test]
async fn tenant_isolation_exact_replay_and_lease_recovery() -> Result<(), Box<dyn Error>> {
    let database_url = std::env::var("CHIO_TEST_POSTGRES_URL")?;
    let migrator_url = std::env::var("CHIO_TEST_POSTGRES_MIGRATOR_URL")?;
    let runtime_url = std::env::var("CHIO_TEST_POSTGRES_RUNTIME_URL")?;
    let retention_url = std::env::var("CHIO_TEST_POSTGRES_RETENTION_URL")?;
    let worker_url = std::env::var("CHIO_TEST_POSTGRES_WORKER_URL")?;
    let replicator_url = std::env::var("CHIO_TEST_POSTGRES_REPLICATOR_URL")?;
    let admin_pool = sqlx::PgPool::connect(&database_url).await?;
    let database_name: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&admin_pool)
        .await?;
    if matches!(
        database_name.as_str(),
        "postgres" | "template0" | "template1"
    ) {
        return Err(std::io::Error::other(
            "postgres integration tests require a dedicated non-system database",
        )
        .into());
    }
    sqlx::raw_sql(
        r#"
        DROP SCHEMA IF EXISTS public CASCADE;
        CREATE SCHEMA public;
        REVOKE ALL ON SCHEMA public FROM PUBLIC;
        "#,
    )
    .execute(&admin_pool)
    .await?;
    sqlx::raw_sql(
        r#"
        DO $role$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chio_market_migrator_test') THEN
                CREATE ROLE chio_market_migrator_test LOGIN PASSWORD 'test-only-password'
                    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
            END IF;
            ALTER ROLE chio_market_migrator_test LOGIN PASSWORD 'test-only-password'
                NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION BYPASSRLS;
            EXECUTE format(
                'REVOKE CREATE, TEMPORARY ON DATABASE %I FROM chio_market_migrator_test',
                current_database()
            );
        END
        $role$;
        GRANT USAGE, CREATE ON SCHEMA public TO chio_market_migrator_test;
        "#,
    )
    .execute(&admin_pool)
    .await?;
    let migrator_pool = sqlx::postgres::PgPoolOptions::new()
        .min_connections(1)
        .max_connections(1)
        .connect(&migrator_url)
        .await?;
    install_legacy_migration_fixture(&migrator_pool).await?;
    sqlx::query(
        r#"INSERT INTO chio_finding_market_tenants (
               tenant_id, enabled, created_at, max_concurrent_jobs,
               max_queued_jobs, max_monthly_spend_units, configuration_revision
           ) VALUES ($1, TRUE, 1700000000, 1, 10, 1000, 'legacy-probe')"#,
    )
    .bind("legacy-principal-probe")
    .execute(&admin_pool)
    .await?;
    sqlx::query(
        r#"INSERT INTO chio_finding_market_principals (
               tenant_id, principal_id, role, capability_public_key_hex,
               enabled, created_at, updated_at
           ) VALUES ($1, 'legacy-buyer', 'buyer', $2, TRUE, 1700000000, 1700000000)"#,
    )
    .bind("legacy-principal-probe")
    .bind("9".repeat(64))
    .execute(&admin_pool)
    .await?;
    let migrator = PostgresFindingMarketMigrator::from_pool_for_integration_tests(migrator_pool);
    assert!(migrator.migrate().await.is_err());
    let migration_eleven_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE version = 11")
            .fetch_one(&admin_pool)
            .await?;
    assert_eq!(migration_eleven_count, 0);
    let retained_legacy_principal_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chio_finding_market_principals WHERE tenant_id = $1",
    )
    .bind("legacy-principal-probe")
    .fetch_one(&admin_pool)
    .await?;
    assert_eq!(retained_legacy_principal_count, 1);
    sqlx::query("DELETE FROM chio_finding_market_principals WHERE tenant_id = $1")
        .bind("legacy-principal-probe")
        .execute(&admin_pool)
        .await?;
    sqlx::query("DELETE FROM chio_finding_market_tenants WHERE tenant_id = $1")
        .bind("legacy-principal-probe")
        .execute(&admin_pool)
        .await?;
    migrator.migrate().await?;
    migrator.migrate().await?;
    let migration_checksum: Vec<u8> =
        sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version = 1")
            .fetch_one(&admin_pool)
            .await?;
    sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = 1")
        .bind(vec![0_u8; migration_checksum.len()])
        .execute(&admin_pool)
        .await?;
    assert!(matches!(
        migrator.migrate().await,
        Err(HostedMarketStoreError::MigrationDrift)
    ));
    sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = 1")
        .bind(migration_checksum)
        .execute(&admin_pool)
        .await?;
    migrator.migrate().await?;
    sqlx::raw_sql(
        r#"
        DO $role$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chio_market_runtime_test') THEN
                CREATE ROLE chio_market_runtime_test LOGIN PASSWORD 'test-only-password'
                    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
            END IF;
            ALTER ROLE chio_market_runtime_test LOGIN PASSWORD 'test-only-password'
                NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
            EXECUTE format(
                'REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC',
                current_database()
            );
            EXECUTE format(
                'REVOKE CREATE, TEMPORARY ON DATABASE %I FROM chio_market_runtime_test',
                current_database()
            );
        END
        $role$;
        GRANT USAGE ON SCHEMA public TO chio_market_runtime_test;
        GRANT SELECT ON _sqlx_migrations TO chio_market_runtime_test;
        REVOKE ALL ON chio_finding_market_tenants, chio_finding_market_jobs,
            chio_finding_market_principals, chio_finding_market_api_keys,
            chio_finding_market_dpop_nonces, chio_finding_market_capability_uses,
            chio_finding_market_security_events, chio_finding_market_aggregate_events,
            chio_finding_market_aggregate_heads,
            chio_finding_market_aggregate_checkpoints,
            chio_finding_market_spend_reservations,
            chio_finding_market_journal_checkpoints,
            chio_finding_market_journal_checkpoint_members,
            chio_finding_market_archive_manifests,
            chio_finding_market_legal_hold_events,
            chio_finding_market_restore_verifications,
            chio_finding_market_quota_alerts,
            chio_finding_market_gc_receipts,
            chio_finding_market_domain_event_contracts,
            chio_finding_market_domain_projections,
            chio_finding_market_principal_events,
            chio_finding_market_principal_key_overlaps,
            chio_finding_market_authority_state,
            chio_finding_market_replication_events,
            chio_finding_market_principal_replication_events,
            chio_finding_market_replication_checks,
            chio_finding_market_replication_outbox,
            chio_finding_market_principal_replication_outbox,
            chio_finding_market_authority_transitions
            FROM chio_market_runtime_test;
        GRANT SELECT, INSERT, UPDATE ON chio_finding_market_tenants TO chio_market_runtime_test;
        GRANT SELECT, INSERT, UPDATE ON chio_finding_market_jobs TO chio_market_runtime_test;
        GRANT SELECT ON chio_finding_market_principals TO chio_market_runtime_test;
        GRANT SELECT, INSERT, UPDATE ON chio_finding_market_api_keys TO chio_market_runtime_test;
        GRANT SELECT, INSERT, DELETE ON chio_finding_market_dpop_nonces TO chio_market_runtime_test;
        GRANT SELECT, INSERT, UPDATE, DELETE ON chio_finding_market_capability_uses TO chio_market_runtime_test;
        GRANT SELECT, INSERT ON chio_finding_market_security_events TO chio_market_runtime_test;
        GRANT SELECT ON chio_finding_market_aggregate_events TO chio_market_runtime_test;
        GRANT SELECT ON chio_finding_market_aggregate_heads TO chio_market_runtime_test;
        GRANT SELECT, INSERT ON chio_finding_market_aggregate_checkpoints TO chio_market_runtime_test;
        GRANT SELECT, INSERT, UPDATE ON chio_finding_market_spend_reservations TO chio_market_runtime_test;
        GRANT SELECT ON chio_finding_market_domain_event_contracts,
            chio_finding_market_domain_projections,
            chio_finding_market_principal_events,
            chio_finding_market_principal_key_overlaps,
            chio_finding_market_authority_state
            TO chio_market_runtime_test;
        GRANT EXECUTE ON FUNCTION chio_finding_market_append_domain_event(
            TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT, BYTEA, TEXT, BIGINT
        ) TO chio_market_runtime_test;
        GRANT EXECUTE ON FUNCTION chio_finding_market_apply_principal_event(
            TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, BYTEA, BIGINT
        ) TO chio_market_runtime_test;
        "#,
    )
    .execute(&admin_pool)
    .await?;
    sqlx::raw_sql(
        r#"
        DO $role$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chio_market_retention_test') THEN
                CREATE ROLE chio_market_retention_test LOGIN PASSWORD 'test-only-password'
                    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
            END IF;
            ALTER ROLE chio_market_retention_test LOGIN PASSWORD 'test-only-password'
                NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
            EXECUTE format(
                'REVOKE CREATE, TEMPORARY ON DATABASE %I FROM chio_market_retention_test',
                current_database()
            );
        END
        $role$;
        GRANT USAGE ON SCHEMA public TO chio_market_retention_test;
        GRANT SELECT ON _sqlx_migrations, chio_finding_market_tenants,
            chio_finding_market_jobs, chio_finding_market_aggregate_events,
            chio_finding_market_aggregate_heads,
            chio_finding_market_aggregate_checkpoints,
            chio_finding_market_gc_receipts
            TO chio_market_retention_test;
        GRANT SELECT ON chio_finding_market_journal_checkpoints,
            chio_finding_market_journal_checkpoint_members,
            chio_finding_market_archive_manifests,
            chio_finding_market_legal_hold_events,
            chio_finding_market_restore_verifications,
            chio_finding_market_quota_alerts
            TO chio_market_retention_test;
        GRANT EXECUTE ON FUNCTION chio_finding_market_append_journal_checkpoint(
            TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, BYTEA, BIGINT, JSONB
        ) TO chio_market_retention_test;
        GRANT EXECUTE ON FUNCTION chio_finding_market_append_archive_manifest(
            TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, TEXT, TEXT,
            BIGINT, TEXT, TEXT, TEXT, BYTEA, BIGINT
        ) TO chio_market_retention_test;
        GRANT EXECUTE ON FUNCTION chio_finding_market_append_legal_hold_event(
            TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BYTEA, BIGINT
        ) TO chio_market_retention_test;
        GRANT EXECUTE ON FUNCTION chio_finding_market_append_restore_verification(
            TEXT, TEXT, TEXT, TEXT, TEXT, BYTEA, BIGINT
        ) TO chio_market_retention_test;
        GRANT EXECUTE ON FUNCTION chio_finding_market_append_quota_alert(
            TEXT, TEXT, TEXT, BIGINT, BIGINT, TEXT, BYTEA, BIGINT
        ) TO chio_market_retention_test;
        GRANT EXECUTE ON FUNCTION chio_finding_market_gc_retained_resource(
            TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, TEXT, BYTEA, BIGINT
        ) TO chio_market_retention_test;
        "#,
    )
    .execute(&admin_pool)
    .await?;
    sqlx::raw_sql(
        r#"
        DO $role$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chio_market_worker_test') THEN
                CREATE ROLE chio_market_worker_test LOGIN PASSWORD 'test-only-password'
                    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
            END IF;
            ALTER ROLE chio_market_worker_test LOGIN PASSWORD 'test-only-password'
                NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
            EXECUTE format(
                'REVOKE CREATE, TEMPORARY ON DATABASE %I FROM chio_market_worker_test',
                current_database()
            );
        END
        $role$;
        GRANT USAGE ON SCHEMA public TO chio_market_worker_test;
        GRANT SELECT ON _sqlx_migrations, chio_finding_market_tenants
            TO chio_market_worker_test;
        GRANT SELECT, UPDATE ON chio_finding_market_jobs TO chio_market_worker_test;
        "#,
    )
    .execute(&admin_pool)
    .await?;
    sqlx::raw_sql(
        r#"
        DO $role$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chio_market_replicator_test') THEN
                CREATE ROLE chio_market_replicator_test LOGIN PASSWORD 'test-only-password'
                    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
            END IF;
            ALTER ROLE chio_market_replicator_test LOGIN PASSWORD 'test-only-password'
                NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
            EXECUTE format(
                'REVOKE CREATE, TEMPORARY ON DATABASE %I FROM chio_market_replicator_test',
                current_database()
            );
        END
        $role$;
        GRANT USAGE ON SCHEMA public TO chio_market_replicator_test;
        GRANT SELECT ON _sqlx_migrations, chio_finding_market_tenants,
            chio_finding_market_aggregate_events,
            chio_finding_market_aggregate_heads,
            chio_finding_market_domain_event_contracts,
            chio_finding_market_domain_projections,
            chio_finding_market_principals,
            chio_finding_market_principal_events,
            chio_finding_market_principal_key_overlaps,
            chio_finding_market_authority_state,
            chio_finding_market_replication_events,
            chio_finding_market_principal_replication_events,
            chio_finding_market_replication_outbox,
            chio_finding_market_principal_replication_outbox,
            chio_finding_market_authority_transitions
            TO chio_market_replicator_test;
        GRANT SELECT ON chio_finding_market_replication_checks
            TO chio_market_replicator_test;
        GRANT EXECUTE ON FUNCTION chio_finding_market_append_replication_check(
            TEXT, TEXT, TEXT, BIGINT, BIGINT, TEXT, TEXT, BIGINT, BIGINT,
            BIGINT, TEXT, BYTEA, BIGINT
        ) TO chio_market_replicator_test;
        GRANT EXECUTE ON FUNCTION chio_finding_market_apply_replication_event(
            TEXT, TEXT, TEXT, BIGINT, BIGINT, TEXT, TEXT, BIGINT, TEXT, TEXT,
            TEXT, TEXT, TEXT, BYTEA, TEXT, TEXT, BYTEA, BIGINT
        ) TO chio_market_replicator_test;
        GRANT EXECUTE ON FUNCTION chio_finding_market_apply_principal_replication_event(
            TEXT, TEXT, TEXT, BIGINT, BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT,
            BIGINT, TEXT, TEXT, BYTEA, TEXT, BYTEA, BIGINT
        ) TO chio_market_replicator_test;
        GRANT EXECUTE ON FUNCTION chio_finding_market_apply_authority_transition(
            TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, BIGINT, BIGINT, TEXT, TEXT,
            TEXT, BIGINT, TEXT, BYTEA, BIGINT
        ) TO chio_market_replicator_test;
        "#,
    )
    .execute(&admin_pool)
    .await?;
    let runtime_pool = sqlx::PgPool::connect(&runtime_url).await?;
    let store =
        PostgresFindingMarketStore::from_pool_for_integration_tests(runtime_pool.clone(), 8);
    store
        .verify_runtime_boundary_for_integration_tests()
        .await?;
    let retention_pool = sqlx::PgPool::connect(&retention_url).await?;
    let retention =
        PostgresFindingMarketRetention::from_pool_for_integration_tests(retention_pool.clone());
    retention
        .verify_retention_boundary_for_integration_tests()
        .await?;
    let worker_pool = sqlx::PgPool::connect(&worker_url).await?;
    let worker_store = PostgresFindingMarketStore::from_pool_for_integration_tests(worker_pool, 8);
    worker_store
        .verify_worker_boundary_for_integration_tests()
        .await?;
    let replicator_pool = sqlx::PgPool::connect(&replicator_url).await?;
    let replicator =
        PostgresFindingMarketReplicator::from_pool_for_integration_tests(replicator_pool);
    replicator
        .verify_replicator_boundary_for_integration_tests()
        .await?;
    let migration_ledger_tamper = sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 1")
        .execute(&runtime_pool)
        .await;
    assert!(migration_ledger_tamper.is_err());

    sqlx::raw_sql(
        "GRANT UPDATE ON chio_finding_market_aggregate_events TO chio_market_runtime_test",
    )
    .execute(&admin_pool)
    .await?;
    assert!(matches!(
        store.verify_runtime_boundary_for_integration_tests().await,
        Err(HostedMarketStoreError::Configuration)
    ));
    sqlx::raw_sql(
        "REVOKE UPDATE ON chio_finding_market_aggregate_events FROM chio_market_runtime_test",
    )
    .execute(&admin_pool)
    .await?;
    store
        .verify_runtime_boundary_for_integration_tests()
        .await?;

    sqlx::raw_sql(
        "CREATE ROLE chio_market_runtime_parent NOLOGIN; GRANT chio_market_runtime_parent TO chio_market_runtime_test",
    )
    .execute(&admin_pool)
    .await?;
    assert!(matches!(
        store.verify_runtime_boundary_for_integration_tests().await,
        Err(HostedMarketStoreError::Configuration)
    ));
    sqlx::raw_sql(
        "REVOKE chio_market_runtime_parent FROM chio_market_runtime_test; DROP ROLE chio_market_runtime_parent",
    )
    .execute(&admin_pool)
    .await?;
    store
        .verify_runtime_boundary_for_integration_tests()
        .await?;

    sqlx::raw_sql(
        "DROP POLICY IF EXISTS chio_finding_market_tenants_drift_probe ON chio_finding_market_tenants; CREATE POLICY chio_finding_market_tenants_drift_probe ON chio_finding_market_tenants USING (TRUE) WITH CHECK (TRUE)",
    )
    .execute(&admin_pool)
    .await?;
    assert!(matches!(
        store.verify_runtime_boundary_for_integration_tests().await,
        Err(HostedMarketStoreError::Configuration)
    ));
    sqlx::raw_sql(
        "DROP POLICY chio_finding_market_tenants_drift_probe ON chio_finding_market_tenants",
    )
    .execute(&admin_pool)
    .await?;
    store
        .verify_runtime_boundary_for_integration_tests()
        .await?;
    sqlx::raw_sql(
        r#"
        DROP POLICY chio_finding_market_tenants_tenant_isolation
            ON chio_finding_market_tenants;
        CREATE POLICY chio_finding_market_tenants_tenant_isolation
            ON chio_finding_market_tenants
            USING (
                tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), '')
                OR TRUE
            )
            WITH CHECK (
                tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), '')
                OR TRUE
            );
        "#,
    )
    .execute(&admin_pool)
    .await?;
    assert!(matches!(
        store.verify_runtime_boundary_for_integration_tests().await,
        Err(HostedMarketStoreError::Configuration)
    ));
    sqlx::raw_sql(
        r#"
        DROP POLICY chio_finding_market_tenants_tenant_isolation
            ON chio_finding_market_tenants;
        CREATE POLICY chio_finding_market_tenants_tenant_isolation
            ON chio_finding_market_tenants
            USING (
                tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), '')
            )
            WITH CHECK (
                tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), '')
            );
        "#,
    )
    .execute(&admin_pool)
    .await?;
    store
        .verify_runtime_boundary_for_integration_tests()
        .await?;

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let tenant_a = HostedTenantId::new(format!("integration-a-{nonce}"))?;
    let tenant_b = HostedTenantId::new(format!("integration-b-{nonce}"))?;
    let tenant_limits = HostedTenantLimits::new(1, 8, 10_000, "integration-revision-1")?;
    store
        .register_tenant(&tenant_a, &tenant_limits, 1_700_000_000)
        .await?;
    store
        .register_tenant(&tenant_b, &tenant_limits, 1_700_000_000)
        .await?;
    store
        .verify_tenant_limits(&tenant_a, &tenant_limits)
        .await?;
    assert!(matches!(
        store
            .register_tenant(
                &tenant_a,
                &HostedTenantLimits::new(2, 8, 10_000, "integration-revision-1")?,
                1_700_000_000,
            )
            .await,
        Err(HostedMarketStoreError::Conflict)
    ));
    assert_eq!(
        store
            .reserve_monthly_spend(&tenant_a, "purchase-spend-1", 6_000, 1_700_000_001,)
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    assert_eq!(
        store
            .reserve_monthly_spend(&tenant_a, "purchase-spend-1", 6_000, 1_700_000_002,)
            .await?,
        HostedJobWriteOutcome::ExactReplay
    );
    assert!(matches!(
        store
            .reserve_monthly_spend(&tenant_a, "purchase-spend-2", 4_001, 1_700_000_002,)
            .await,
        Err(HostedMarketStoreError::Capacity)
    ));
    assert_eq!(
        store
            .commit_monthly_spend(&tenant_a, "purchase-spend-1", 1_700_000_003)
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    assert_eq!(
        store
            .commit_monthly_spend(&tenant_a, "purchase-spend-1", 1_700_000_004)
            .await?,
        HostedJobWriteOutcome::ExactReplay
    );
    assert!(matches!(
        store
            .reserve_monthly_spend(&tenant_a, "purchase-spend-1", 6_000, 1_700_000_005,)
            .await,
        Err(HostedMarketStoreError::Conflict)
    ));
    assert!(matches!(
        store
            .release_monthly_spend(&tenant_a, "purchase-spend-1", 1_700_000_005)
            .await,
        Err(HostedMarketStoreError::Conflict)
    ));
    let committed_spend = store
        .monthly_spend_reservation(&tenant_a, "purchase-spend-1")
        .await?
        .ok_or("monthly spend reservation missing")?;
    assert_eq!(
        committed_spend.state,
        chio_finding_market_store_postgres::HostedSpendState::Committed
    );
    assert_eq!(committed_spend.billing_period, "2023-11");
    assert!(store
        .monthly_spend_reservation(&tenant_b, "purchase-spend-1")
        .await?
        .is_none());
    store
        .reserve_monthly_spend(&tenant_a, "purchase-spend-release", 4_000, 1_700_000_006)
        .await?;
    assert!(matches!(
        store
            .release_monthly_spend(&tenant_a, "purchase-spend-release", 1_700_000_005,)
            .await,
        Err(HostedMarketStoreError::Invalid("spend time"))
    ));
    store
        .release_monthly_spend(&tenant_a, "purchase-spend-release", 1_700_000_007)
        .await?;
    assert_eq!(
        store
            .reserve_monthly_spend(
                &tenant_a,
                "purchase-spend-after-release",
                4_000,
                1_700_000_008,
            )
            .await?,
        HostedJobWriteOutcome::Inserted
    );

    let unscoped_tenant_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM chio_finding_market_tenants")
            .fetch_one(&runtime_pool)
            .await?;
    assert_eq!(
        unscoped_tenant_count, 0,
        "tenant registry must require tenant context"
    );
    let mut tenant_a_transaction = runtime_pool.begin().await?;
    sqlx::query("SELECT set_config('chio.tenant_id', $1, TRUE)")
        .bind(tenant_a.as_str())
        .execute(&mut *tenant_a_transaction)
        .await?;
    let cross_tenant_update =
        sqlx::query("UPDATE chio_finding_market_tenants SET enabled = FALSE WHERE tenant_id = $1")
            .bind(tenant_b.as_str())
            .execute(&mut *tenant_a_transaction)
            .await?;
    assert_eq!(cross_tenant_update.rows_affected(), 0);
    tenant_a_transaction.rollback().await?;

    let operator_signer = Keypair::from_seed(&[89_u8; 32]);
    let source_signer = Keypair::from_seed(&[87_u8; 32]);
    let buyer_capability_signer = Keypair::from_seed(&[88_u8; 32]);
    let provision = SignedExportEnvelope::sign(
        HostedPrincipalLifecycleBody {
            schema: HOSTED_PRINCIPAL_LIFECYCLE_SCHEMA.to_owned(),
            tenant_id: tenant_a.as_str().to_owned(),
            principal_id: "buyer-a".to_owned(),
            operation: HostedPrincipalLifecycleOperation::Provision,
            role: HostedPrincipalRole::Buyer,
            capability_public_key_hex: Some(buyer_capability_signer.public_key().to_hex()),
            overlap_expires_at: None,
            previous_event_sha256: None,
            created_at: 1_700_000_000,
        },
        &operator_signer,
    )?;
    assert!(matches!(
        store
            .apply_principal_lifecycle(&tenant_a, &operator_signer.public_key(), &provision)
            .await,
        Err(HostedMarketStoreError::Conflict)
    ));
    let replicated_provision =
        signed_principal_replication_event(&tenant_a, 1, provision.clone(), &source_signer)?;
    assert_eq!(
        replicator
            .apply_principal_replication_event(
                &tenant_a,
                &source_signer.public_key(),
                &operator_signer.public_key(),
                &replicated_provision,
            )
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    assert_eq!(
        replicator
            .apply_principal_replication_event(
                &tenant_a,
                &source_signer.public_key(),
                &operator_signer.public_key(),
                &replicated_provision,
            )
            .await?,
        HostedJobWriteOutcome::ExactReplay
    );
    let provision_sha256 = sha256_hex(&canonical_json_bytes(&provision)?);
    let rotated_capability_signer = Keypair::from_seed(&[86_u8; 32]);
    let rotation = SignedExportEnvelope::sign(
        HostedPrincipalLifecycleBody {
            schema: HOSTED_PRINCIPAL_LIFECYCLE_SCHEMA.to_owned(),
            tenant_id: tenant_a.as_str().to_owned(),
            principal_id: "buyer-a".to_owned(),
            operation: HostedPrincipalLifecycleOperation::KeyRotation,
            role: HostedPrincipalRole::Buyer,
            capability_public_key_hex: Some(rotated_capability_signer.public_key().to_hex()),
            overlap_expires_at: Some(1_700_000_100),
            previous_event_sha256: Some(provision_sha256),
            created_at: 1_700_000_010,
        },
        &operator_signer,
    )?;
    let rotation_sha256 = sha256_hex(&canonical_json_bytes(&rotation)?);
    let replicated_rotation =
        signed_principal_replication_event(&tenant_a, 2, rotation, &source_signer)?;
    assert_eq!(
        replicator
            .apply_principal_replication_event(
                &tenant_a,
                &source_signer.public_key(),
                &operator_signer.public_key(),
                &replicated_rotation,
            )
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    assert!(store
        .get_principal_by_capability_key(
            &tenant_a,
            &buyer_capability_signer.public_key().to_hex(),
            1_700_000_050,
        )
        .await?
        .is_some());
    assert!(store
        .get_principal_by_capability_key(
            &tenant_a,
            &buyer_capability_signer.public_key().to_hex(),
            1_700_000_101,
        )
        .await?
        .is_none());
    assert!(store
        .get_principal_by_capability_key(
            &tenant_a,
            &rotated_capability_signer.public_key().to_hex(),
            1_700_000_101,
        )
        .await?
        .is_some());
    store
        .put_api_key(
            &tenant_a,
            "key-a",
            "buyer-a",
            &"c".repeat(64),
            &["finding.purchase".to_owned()]
                .into_iter()
                .collect::<BTreeSet<_>>(),
            1_700_000_000,
            1_700_003_600,
            None,
            1_700_000_000,
        )
        .await?;
    assert!(store
        .get_active_api_key(&tenant_a, "key-a", 1_700_000_001)
        .await?
        .is_some());
    assert!(store
        .get_active_api_key(&tenant_b, "key-a", 1_700_000_001)
        .await?
        .is_none());
    let actions = ["finding.purchase".to_owned()]
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        store
            .put_api_key_with_security_event(
                &tenant_a,
                "key-b",
                "buyer-a",
                &"e".repeat(64),
                &actions,
                1_700_000_000,
                1_700_003_600,
                Some("key-a"),
                "event-key-b-issued",
                "hosted.api_key.issued",
                br#"{"event":"issue"}"#,
                1_700_000_000,
            )
            .await?,
        HostedJobWriteOutcome::Inserted
    );

    let domain_signer = Keypair::from_seed(&[90_u8; 32]);
    let aggregate_payload = signed_domain_payload(
        HostedMarketDomainEventKind::FindingPublished,
        &domain_signer,
        serde_json::json!({"challengeId": "challenge-a", "state": "submitted"}),
    )?;
    let market_finding: Finding = serde_json::from_slice(&aggregate_payload)?;
    let market_finding_id = market_finding.finding_id.clone();
    let market_artifact = HostedMarketDomainArtifact::Finding(market_finding.clone());
    assert!(matches!(
        HostedMarketDomainEvent::from_artifact(
            "wrong-finding-id",
            "wrong-finding-identity",
            &market_artifact,
        ),
        Err(HostedMarketStoreError::Invalid("domain aggregate identity"))
    ));
    let submitted_event = HostedMarketDomainEvent::from_artifact(
        market_finding_id.clone(),
        "challenge-a-submitted",
        &market_artifact,
    )?;
    let shadow_append = store
        .append_domain_event(&tenant_a, &submitted_event, 0, None, 1_700_000_001)
        .await;
    assert!(
        matches!(shadow_append, Err(HostedMarketStoreError::Conflict)),
        "shadow authority admitted a market mutation: {shadow_append:?}"
    );
    let replicated_submission = SignedExportEnvelope::sign(
        HostedReplicationEventBody {
            schema: HOSTED_REPLICATION_EVENT_SCHEMA.to_owned(),
            tenant_id: tenant_a.as_str().to_owned(),
            source_authority: HostedMarketAuthority::Sqlite,
            authority_epoch: 1,
            sequence: 3,
            event_kind: HostedMarketDomainEventKind::FindingPublished,
            aggregate_id: market_finding_id.clone(),
            event_id: "challenge-a-submitted".to_owned(),
            expected_revision: 0,
            expected_event_sha256: None,
            artifact_signer_key: Some(domain_signer.public_key()),
            payload: serde_json::from_slice(&aggregate_payload)?,
            committed_at: 1_700_000_001,
        },
        &source_signer,
    )?;
    let unsupported_replication = SignedExportEnvelope::sign(
        HostedReplicationEventBody {
            schema: HOSTED_REPLICATION_EVENT_SCHEMA.to_owned(),
            tenant_id: tenant_a.as_str().to_owned(),
            source_authority: HostedMarketAuthority::Sqlite,
            authority_epoch: 1,
            sequence: 3,
            event_kind: HostedMarketDomainEventKind::PenaltyAssessed,
            aggregate_id: "unsupported-penalty".to_owned(),
            event_id: "unsupported-penalty-event".to_owned(),
            expected_revision: 0,
            expected_event_sha256: None,
            artifact_signer_key: Some(domain_signer.public_key()),
            payload: serde_json::from_slice(&aggregate_payload)?,
            committed_at: 1_700_000_001,
        },
        &source_signer,
    )?;
    assert!(matches!(
        replicator
            .apply_replication_event(
                &tenant_a,
                &source_signer.public_key(),
                &unsupported_replication,
            )
            .await,
        Err(HostedMarketStoreError::Invalid(
            "unsupported hosted domain artifact"
        ))
    ));
    assert_eq!(
        replicator
            .apply_replication_event(
                &tenant_a,
                &source_signer.public_key(),
                &replicated_submission,
            )
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    assert_eq!(
        replicator
            .apply_replication_event(
                &tenant_a,
                &source_signer.public_key(),
                &replicated_submission,
            )
            .await?,
        HostedJobWriteOutcome::ExactReplay
    );
    let authority_now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let projection_sha256 = replicator.target_projection_sha256(&tenant_a).await?;
    append_replication_check(
        &replicator,
        &tenant_a,
        &source_signer,
        ReplicationCheckSpec {
            authority_epoch: 1,
            through_sequence: 3,
            projection_sha256: &projection_sha256,
            source_authority: HostedMarketAuthority::Sqlite,
            checked_at: authority_now,
        },
    )
    .await?;
    apply_authority_transition(
        &replicator,
        &tenant_a,
        &source_signer,
        HostedAuthorityTransitionOperation::Freeze,
        HostedMarketAuthority::Sqlite,
        HostedMarketAuthority::Sqlite,
        1,
        2,
        3,
        &projection_sha256,
        None,
        authority_now,
    )
    .await?;
    append_replication_check(
        &replicator,
        &tenant_a,
        &source_signer,
        ReplicationCheckSpec {
            authority_epoch: 2,
            through_sequence: 3,
            projection_sha256: &projection_sha256,
            source_authority: HostedMarketAuthority::Sqlite,
            checked_at: authority_now,
        },
    )
    .await?;
    apply_authority_transition(
        &replicator,
        &tenant_a,
        &source_signer,
        HostedAuthorityTransitionOperation::Cutover,
        HostedMarketAuthority::Sqlite,
        HostedMarketAuthority::Postgres,
        2,
        3,
        3,
        &projection_sha256,
        Some(authority_now + 604_800),
        authority_now,
    )
    .await?;
    append_replication_check(
        &replicator,
        &tenant_a,
        &source_signer,
        ReplicationCheckSpec {
            authority_epoch: 3,
            through_sequence: 0,
            projection_sha256: &projection_sha256,
            source_authority: HostedMarketAuthority::Postgres,
            checked_at: authority_now,
        },
    )
    .await?;
    let head = store
        .aggregate_head(&tenant_a, HostedAggregateKind::Finding, &market_finding_id)
        .await?
        .ok_or("aggregate head missing")?;
    assert_eq!(head.revision, 1);
    assert!(store
        .aggregate_head(&tenant_b, HostedAggregateKind::Finding, &market_finding_id,)
        .await?
        .is_none());
    let advanced_event = HostedMarketDomainEvent::from_artifact(
        market_finding_id.clone(),
        "challenge-a-evaluating",
        &market_artifact,
    )?;
    store
        .append_domain_event(
            &tenant_a,
            &advanced_event,
            head.revision,
            Some(&head.event_sha256),
            authority_now,
        )
        .await?;
    let rollback_outbox = replicator
        .pending_rollback_outbox(&tenant_a, 3, 0, 10)
        .await?;
    assert_eq!(rollback_outbox.len(), 1);
    assert_eq!(rollback_outbox[0].sequence, 1);
    assert_eq!(rollback_outbox[0].event_id, "challenge-a-evaluating");
    let unmirrored_payload = signed_domain_payload(
        HostedMarketDomainEventKind::FindingPublished,
        &domain_signer,
        serde_json::json!({"challengeId": "challenge-unmirrored", "state": "submitted"}),
    )?;
    let unmirrored_finding: Finding = serde_json::from_slice(&unmirrored_payload)?;
    let unmirrored_finding_id = unmirrored_finding.finding_id.clone();
    let unmirrored_event = HostedMarketDomainEvent::from_artifact(
        unmirrored_finding_id,
        "challenge-unmirrored-submitted",
        &HostedMarketDomainArtifact::Finding(unmirrored_finding),
    )?;
    assert!(matches!(
        store
            .append_domain_event(&tenant_a, &unmirrored_event, 0, None, 1_700_000_003)
            .await,
        Err(HostedMarketStoreError::Conflict)
    ));
    let projection_sha256 = replicator.target_projection_sha256(&tenant_a).await?;
    append_replication_check(
        &replicator,
        &tenant_a,
        &source_signer,
        ReplicationCheckSpec {
            authority_epoch: 3,
            through_sequence: 1,
            projection_sha256: &projection_sha256,
            source_authority: HostedMarketAuthority::Postgres,
            checked_at: authority_now,
        },
    )
    .await?;
    let post_cutover_capability_signer = Keypair::from_seed(&[85_u8; 32]);
    let post_cutover_rotation = SignedExportEnvelope::sign(
        HostedPrincipalLifecycleBody {
            schema: HOSTED_PRINCIPAL_LIFECYCLE_SCHEMA.to_owned(),
            tenant_id: tenant_a.as_str().to_owned(),
            principal_id: "buyer-a".to_owned(),
            operation: HostedPrincipalLifecycleOperation::KeyRotation,
            role: HostedPrincipalRole::Buyer,
            capability_public_key_hex: Some(post_cutover_capability_signer.public_key().to_hex()),
            overlap_expires_at: Some(authority_now + 100),
            previous_event_sha256: Some(rotation_sha256),
            created_at: authority_now,
        },
        &operator_signer,
    )?;
    assert_eq!(
        store
            .apply_principal_lifecycle(
                &tenant_a,
                &operator_signer.public_key(),
                &post_cutover_rotation,
            )
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    let rollback_batch = replicator
        .pending_rollback_batch(&tenant_a, 3, 0, 10)
        .await?;
    assert_eq!(rollback_batch.len(), 2);
    assert!(matches!(
        &rollback_batch[0],
        HostedRollbackOutboxEntry::Domain(record)
            if record.sequence == 1 && record.event_id == "challenge-a-evaluating"
    ));
    assert!(matches!(
        &rollback_batch[1],
        HostedRollbackOutboxEntry::Principal(record)
            if record.sequence == 2
                && record.principal_id == "buyer-a"
                && record.operation == HostedPrincipalLifecycleOperation::KeyRotation
    ));
    let projection_sha256 = replicator.target_projection_sha256(&tenant_a).await?;
    append_replication_check(
        &replicator,
        &tenant_a,
        &source_signer,
        ReplicationCheckSpec {
            authority_epoch: 3,
            through_sequence: 2,
            projection_sha256: &projection_sha256,
            source_authority: HostedMarketAuthority::Postgres,
            checked_at: authority_now,
        },
    )
    .await?;
    let history = store
        .aggregate_history(
            &tenant_a,
            HostedAggregateKind::Finding,
            &market_finding_id,
            10,
        )
        .await?;
    assert_eq!(history.len(), 2);
    assert_eq!(
        history[1].previous_event_sha256.as_deref(),
        Some(history[0].event_sha256.as_str())
    );
    assert!(matches!(
        store
            .aggregate_history(
                &tenant_a,
                HostedAggregateKind::Finding,
                &market_finding_id,
                1,
            )
            .await,
        Err(HostedMarketStoreError::Capacity)
    ));
    assert!(matches!(
        store
            .append_domain_event(
                &tenant_a,
                &HostedMarketDomainEvent::from_artifact(
                    market_finding_id.clone(),
                    "challenge-a-stale",
                    &market_artifact,
                )?,
                head.revision,
                Some(&head.event_sha256),
                1_700_000_003,
            )
            .await,
        Err(HostedMarketStoreError::Conflict)
    ));

    let aggregate_tamper = sqlx::query(
        "UPDATE chio_finding_market_aggregate_events SET event_sha256 = $1 WHERE tenant_id = $2 AND event_id = $3",
    )
    .bind("f".repeat(64))
    .bind(tenant_a.as_str())
    .bind("challenge-a-submitted")
    .execute(&admin_pool)
    .await;
    assert!(aggregate_tamper.is_err());

    let checkpoint_signer = Keypair::from_seed(&[91_u8; 32]);
    let checkpoint = SignedExportEnvelope::sign(
        HostedAggregateCheckpointBody {
            schema: HOSTED_AGGREGATE_CHECKPOINT_SCHEMA.to_owned(),
            tenant_id: tenant_a.as_str().to_owned(),
            aggregate_kind: HostedAggregateKind::Finding,
            aggregate_id: market_finding_id.clone(),
            revision: 2,
            event_sha256: history[1].event_sha256.clone(),
            previous_checkpoint_sha256: None,
            created_at: 1_700_000_004,
        },
        &checkpoint_signer,
    )?;
    assert_eq!(
        store
            .append_aggregate_checkpoint(&tenant_a, &checkpoint_signer.public_key(), &checkpoint,)
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    assert_eq!(
        store
            .append_aggregate_checkpoint(&tenant_a, &checkpoint_signer.public_key(), &checkpoint,)
            .await?,
        HostedJobWriteOutcome::ExactReplay
    );
    let retained_checkpoint = store
        .latest_aggregate_checkpoint(
            &tenant_a,
            HostedAggregateKind::Finding,
            &market_finding_id,
            &checkpoint_signer.public_key(),
        )
        .await?
        .ok_or("aggregate checkpoint missing")?;
    assert_eq!(retained_checkpoint.checkpoint, checkpoint);
    assert!(store
        .latest_aggregate_checkpoint(
            &tenant_b,
            HostedAggregateKind::Finding,
            &market_finding_id,
            &checkpoint_signer.public_key(),
        )
        .await?
        .is_none());
    let checkpoint_tamper = sqlx::query(
        "DELETE FROM chio_finding_market_aggregate_checkpoints WHERE tenant_id = $1 AND checkpoint_sha256 = $2",
    )
    .bind(tenant_a.as_str())
    .bind(&retained_checkpoint.checkpoint_sha256)
    .execute(&admin_pool)
    .await;
    assert!(checkpoint_tamper.is_err());

    let archive_payload = signed_domain_payload(
        HostedMarketDomainEventKind::FindingPublished,
        &domain_signer,
        serde_json::json!({"findingId": "archive-finding-a"}),
    )?;
    let archive_finding: Finding = serde_json::from_slice(&archive_payload)?;
    let archive_finding_id = archive_finding.finding_id.clone();
    let archive_event = HostedMarketDomainEvent::from_artifact(
        archive_finding_id.clone(),
        "archive-finding-a-published",
        &HostedMarketDomainArtifact::Finding(archive_finding),
    )?;
    store
        .append_domain_event(&tenant_a, &archive_event, 0, None, authority_now)
        .await?;
    let archive_head = store
        .aggregate_head(&tenant_a, HostedAggregateKind::Finding, &archive_finding_id)
        .await?
        .ok_or("archive aggregate head missing")?;
    let retention_signer = Keypair::from_seed(&[92_u8; 32]);
    let commitment = retention.journal_commitment(&tenant_a).await?;
    let journal_checkpoint = SignedExportEnvelope::sign(
        HostedJournalCheckpointBody {
            schema: HOSTED_JOURNAL_CHECKPOINT_SCHEMA.to_owned(),
            tenant_id: tenant_a.as_str().to_owned(),
            aggregate_heads_sha256: commitment.aggregate_heads_sha256,
            terminal_jobs_sha256: commitment.terminal_jobs_sha256,
            previous_checkpoint_sha256: commitment.previous_checkpoint_sha256,
            migration_version: commitment.migration_version,
            configuration_revision: "integration-revision-1".to_owned(),
            created_at: authority_now,
        },
        &retention_signer,
    )?;
    assert_eq!(
        retention
            .append_journal_checkpoint(
                &tenant_a,
                &retention_signer.public_key(),
                &journal_checkpoint,
            )
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    let journal_checkpoint_sha256 = sha256_hex(&canonical_json_bytes(&journal_checkpoint)?);
    let target = HostedRetentionTarget {
        resource_kind: HostedRetentionResourceKind::Aggregate,
        resource_family: "finding".to_owned(),
        resource_id: archive_finding_id.clone(),
        resource_revision: archive_head.revision,
        resource_sha256: archive_head.event_sha256.clone(),
    };
    let archive_manifest = SignedExportEnvelope::sign(
        HostedArchiveManifestBody {
            schema: HOSTED_ARCHIVE_MANIFEST_SCHEMA.to_owned(),
            tenant_id: tenant_a.as_str().to_owned(),
            target: target.clone(),
            covered_checkpoint_sha256: journal_checkpoint_sha256,
            object_uri: "s3://chio-test/archive-finding-a.json".to_owned(),
            object_sha256: "a".repeat(64),
            object_size: 128,
            configuration_revision: "integration-revision-1".to_owned(),
            previous_archive_sha256: None,
            created_at: authority_now + 1,
        },
        &retention_signer,
    )?;
    assert_eq!(
        retention
            .append_archive_manifest(&tenant_a, &retention_signer.public_key(), &archive_manifest,)
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    let archive_sha256 = sha256_hex(&canonical_json_bytes(&archive_manifest)?);
    let hold = SignedExportEnvelope::sign(
        HostedLegalHoldBody {
            schema: HOSTED_LEGAL_HOLD_SCHEMA.to_owned(),
            tenant_id: tenant_a.as_str().to_owned(),
            hold_id: "legal-hold-a".to_owned(),
            target: target.clone(),
            action: HostedLegalHoldAction::Placed,
            previous_hold_event_sha256: None,
            created_at: authority_now + 2,
        },
        &retention_signer,
    )?;
    retention
        .append_legal_hold(&tenant_a, &retention_signer.public_key(), &hold)
        .await?;
    let hold_sha256 = sha256_hex(&canonical_json_bytes(&hold)?);
    let restore = SignedExportEnvelope::sign(
        HostedRestoreVerificationBody {
            schema: HOSTED_RESTORE_VERIFICATION_SCHEMA.to_owned(),
            tenant_id: tenant_a.as_str().to_owned(),
            archive_sha256: archive_sha256.clone(),
            restored_resource_sha256: target.resource_sha256.clone(),
            verified_at: authority_now + 3,
        },
        &retention_signer,
    )?;
    retention
        .append_restore_verification(&tenant_a, &retention_signer.public_key(), &restore)
        .await?;
    let held_gc_receipt = SignedExportEnvelope::sign(
        HostedGcReceiptBody {
            schema: HOSTED_GC_RECEIPT_SCHEMA.to_owned(),
            tenant_id: tenant_a.as_str().to_owned(),
            archive_sha256: archive_sha256.clone(),
            target: target.clone(),
            completed_at: authority_now + 4,
        },
        &retention_signer,
    )?;
    assert!(matches!(
        retention
            .garbage_collect(&tenant_a, &retention_signer.public_key(), &held_gc_receipt,)
            .await,
        Err(HostedMarketStoreError::RetentionHeld)
    ));
    let release = SignedExportEnvelope::sign(
        HostedLegalHoldBody {
            schema: HOSTED_LEGAL_HOLD_SCHEMA.to_owned(),
            tenant_id: tenant_a.as_str().to_owned(),
            hold_id: "legal-hold-a".to_owned(),
            target: target.clone(),
            action: HostedLegalHoldAction::Released,
            previous_hold_event_sha256: Some(hold_sha256),
            created_at: authority_now + 5,
        },
        &retention_signer,
    )?;
    retention
        .append_legal_hold(&tenant_a, &retention_signer.public_key(), &release)
        .await?;
    let gc_receipt = SignedExportEnvelope::sign(
        HostedGcReceiptBody {
            schema: HOSTED_GC_RECEIPT_SCHEMA.to_owned(),
            tenant_id: tenant_a.as_str().to_owned(),
            archive_sha256: archive_sha256.clone(),
            target: target.clone(),
            completed_at: authority_now + 6,
        },
        &retention_signer,
    )?;
    assert_eq!(
        retention
            .garbage_collect(&tenant_a, &retention_signer.public_key(), &gc_receipt,)
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    assert!(store
        .aggregate_head(&tenant_a, HostedAggregateKind::Finding, &archive_finding_id,)
        .await?
        .is_none());

    let unscoped_aggregate_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM chio_finding_market_aggregate_events")
            .fetch_one(&runtime_pool)
            .await?;
    assert_eq!(unscoped_aggregate_count, 0);
    assert_eq!(
        store
            .revoke_api_key_with_security_event(
                &tenant_a,
                "key-b",
                1_700_000_100,
                "event-key-b-revoked",
                "hosted.api_key.revoked",
                br#"{"event":"revoke"}"#,
            )
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    assert!(store
        .get_active_api_key(&tenant_a, "key-b", 1_700_000_101)
        .await?
        .is_none());
    let mut event_transaction = runtime_pool.begin().await?;
    sqlx::query("SELECT set_config('chio.tenant_id', $1, TRUE)")
        .bind(tenant_a.as_str())
        .execute(&mut *event_transaction)
        .await?;
    let event_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chio_finding_market_security_events WHERE tenant_id = $1 AND event_id IN ('event-key-b-issued', 'event-key-b-revoked')",
    )
    .bind(tenant_a.as_str())
    .fetch_one(&mut *event_transaction)
    .await?;
    assert_eq!(event_count, 2);
    event_transaction.rollback().await?;
    let security_event_tamper = sqlx::query(
        "DELETE FROM chio_finding_market_security_events WHERE tenant_id = $1 AND event_id = $2",
    )
    .bind(tenant_a.as_str())
    .bind("event-key-b-issued")
    .execute(&admin_pool)
    .await;
    assert!(security_event_tamper.is_err());
    assert!(
        store
            .consume_dpop_nonce(
                &tenant_a,
                "capability-a",
                &"d".repeat(64),
                1_700_000_300,
                1_700_000_001,
                8,
            )
            .await?
    );
    assert!(
        !store
            .consume_dpop_nonce(
                &tenant_a,
                "capability-a",
                &"d".repeat(64),
                1_700_000_300,
                1_700_000_001,
                8,
            )
            .await?
    );
    assert!(
        store
            .consume_capability_use(&tenant_a, "capability-a", 2, 1_700_000_300, 1_700_000_001,)
            .await?
    );
    assert!(
        store
            .consume_capability_use(&tenant_a, "capability-a", 2, 1_700_000_300, 1_700_000_002,)
            .await?
    );
    assert!(
        !store
            .consume_capability_use(&tenant_a, "capability-a", 2, 1_700_000_300, 1_700_000_003,)
            .await?
    );

    let request = "a".repeat(64);
    let payload_a =
        br#"{"findingId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    let payload_b =
        br#"{"findingId":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#;
    let queue_tenant = HostedTenantId::new(format!("integration-queue-{nonce}"))?;
    let queue_limits = HostedTenantLimits::new(1, 1, 10_000, "integration-revision-1")?;
    store
        .register_tenant(&queue_tenant, &queue_limits, 1_700_000_000)
        .await?;
    assert_eq!(
        store
            .put_job(
                &queue_tenant,
                "queue-job-1",
                "finding.verify",
                &request,
                payload_a,
                1_700_000_000,
                1_700_000_000,
            )
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    assert_eq!(
        store
            .put_job(
                &queue_tenant,
                "queue-job-1",
                "finding.verify",
                &request,
                payload_a,
                1_700_000_000,
                1_700_000_001,
            )
            .await?,
        HostedJobWriteOutcome::ExactReplay
    );
    assert!(matches!(
        store
            .put_job(
                &queue_tenant,
                "queue-job-2",
                "finding.verify",
                &request,
                payload_b,
                1_700_000_000,
                1_700_000_001,
            )
            .await,
        Err(HostedMarketStoreError::Capacity)
    ));
    assert_eq!(
        store
            .put_job(
                &tenant_a,
                "job-1",
                "finding.purchase",
                &request,
                payload_a,
                1_700_000_000,
                1_700_000_000,
            )
            .await?,
        HostedJobWriteOutcome::Inserted
    );

    let unscoped_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chio_finding_market_jobs")
        .fetch_one(&runtime_pool)
        .await?;
    assert_eq!(unscoped_count, 0, "missing tenant context must fail closed");
    let mut raw_transaction = runtime_pool.begin().await?;
    sqlx::query("SELECT set_config('chio.tenant_id', $1, TRUE)")
        .bind(tenant_a.as_str())
        .execute(&mut *raw_transaction)
        .await?;
    let visible = sqlx::query("SELECT tenant_id FROM chio_finding_market_jobs")
        .fetch_all(&mut *raw_transaction)
        .await?;
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].try_get::<String, _>(0)?, tenant_a.as_str());
    raw_transaction.rollback().await?;
    assert_eq!(
        store
            .put_job(
                &tenant_a,
                "job-1",
                "finding.purchase",
                &request,
                payload_a,
                1_700_000_000,
                1_700_000_001,
            )
            .await?,
        HostedJobWriteOutcome::ExactReplay
    );
    assert_eq!(
        store
            .put_job(
                &tenant_b,
                "job-1",
                "finding.purchase",
                &request,
                payload_b,
                1_700_000_000,
                1_700_000_000,
            )
            .await?,
        HostedJobWriteOutcome::Inserted
    );

    assert_eq!(
        store
            .get_job(&tenant_a, "job-1")
            .await?
            .ok_or("tenant A job missing")?
            .payload_sha256,
        sha256_hex(payload_a)
    );
    assert_eq!(
        store
            .get_job(&tenant_b, "job-1")
            .await?
            .ok_or("tenant B job missing")?
            .payload_sha256,
        sha256_hex(payload_b)
    );
    store
        .put_job(
            &tenant_a,
            "job-concurrent",
            "finding.verify",
            &"c".repeat(64),
            br#"{"findingId":"concurrency-bound"}"#,
            1_700_000_000,
            1_700_000_009,
        )
        .await?;

    let first_lease = store.claim_due_jobs(&tenant_a, "worker-a", 10, 1).await?;
    assert_eq!(first_lease.len(), 1);
    assert_eq!(first_lease[0].state, HostedJobState::Leased);
    assert!(matches!(
        store.claim_due_jobs(&tenant_a, "worker-b", 10, 2).await,
        Err(HostedMarketStoreError::Invalid("tenant_concurrency"))
    ));
    assert!(store
        .claim_due_jobs(&tenant_a, "worker-b", 10, 1)
        .await?
        .is_empty());
    let first_claim = chio_finding_market_store_postgres::HostedJobLease::new(
        "worker-a",
        first_lease[0].lease_fence,
    )?;
    let renewed = store
        .renew_job_lease(&tenant_a, "job-1", &first_claim, 20)
        .await?;
    assert!(
        renewed.expires_at
            > first_lease[0]
                .lease_expires_at
                .ok_or("lease expiry missing")?,
        "renewal must return a later database-authored expiry"
    );
    sqlx::query(
        "UPDATE chio_finding_market_jobs SET lease_expires_at = floor(extract(epoch from clock_timestamp()))::bigint - 1 WHERE tenant_id = $1 AND job_id = $2",
    )
    .bind(tenant_a.as_str())
    .bind("job-1")
    .execute(&admin_pool)
    .await?;
    let recovered = store.claim_due_jobs(&tenant_a, "worker-a", 10, 1).await?;
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].attempt_count, 2);
    assert!(recovered[0].lease_fence > first_lease[0].lease_fence);
    let stale_lease = chio_finding_market_store_postgres::HostedJobLease::new(
        "worker-a",
        first_lease[0].lease_fence,
    )?;
    let recovered_lease = chio_finding_market_store_postgres::HostedJobLease::new(
        "worker-a",
        recovered[0].lease_fence,
    )?;

    let result = br#"{"status":"settled"}"#;
    assert!(store
        .complete_job(&tenant_a, "job-1", &stale_lease, result)
        .await
        .is_err());
    assert_eq!(
        store
            .complete_job(&tenant_a, "job-1", &recovered_lease, result)
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    let completed = store
        .get_job(&tenant_a, "job-1")
        .await?
        .ok_or("completed job missing")?;
    assert_eq!(completed.state, HostedJobState::Completed);
    assert_eq!(
        completed.result_sha256.as_deref(),
        Some(sha256_hex(result).as_str())
    );
    let second_lease = store.claim_due_jobs(&tenant_a, "worker-b", 10, 1).await?;
    assert_eq!(second_lease.len(), 1);
    assert_eq!(second_lease[0].job_id, "job-concurrent");
    let second_claim = chio_finding_market_store_postgres::HostedJobLease::new(
        "worker-b",
        second_lease[0].lease_fence,
    )?;
    store
        .complete_job(&tenant_a, "job-concurrent", &second_claim, result)
        .await?;
    store
        .put_job(
            &tenant_a,
            "job-exhausted",
            "finding.verify",
            &"b".repeat(64),
            br#"{"findingId":"terminal"}"#,
            1_700_000_025,
            1_700_000_025,
        )
        .await?;
    let exhausted_lease = store.claim_due_jobs(&tenant_a, "worker-c", 10, 1).await?;
    assert_eq!(exhausted_lease.len(), 1);
    let exhausted_claim = chio_finding_market_store_postgres::HostedJobLease::new(
        "worker-c",
        exhausted_lease[0].lease_fence,
    )?;
    store
        .exhaust_job(
            &tenant_a,
            "job-exhausted",
            &exhausted_claim,
            "attempt_budget_exhausted",
        )
        .await?;
    let exhausted = store
        .get_job(&tenant_a, "job-exhausted")
        .await?
        .ok_or("exhausted job missing")?;
    assert_eq!(exhausted.state, HostedJobState::Exhausted);
    assert!(store
        .claim_due_jobs(&tenant_a, "worker-d", 10, 1)
        .await?
        .is_empty());
    let terminal_commitment = retention.journal_commitment(&tenant_a).await?;
    let terminal_checkpoint = SignedExportEnvelope::sign(
        HostedJournalCheckpointBody {
            schema: HOSTED_JOURNAL_CHECKPOINT_SCHEMA.to_owned(),
            tenant_id: tenant_a.as_str().to_owned(),
            aggregate_heads_sha256: terminal_commitment.aggregate_heads_sha256,
            terminal_jobs_sha256: terminal_commitment.terminal_jobs_sha256,
            previous_checkpoint_sha256: terminal_commitment.previous_checkpoint_sha256,
            migration_version: terminal_commitment.migration_version,
            configuration_revision: "integration-revision-1".to_owned(),
            created_at: authority_now + 7,
        },
        &retention_signer,
    )?;
    assert_eq!(
        retention
            .append_journal_checkpoint(
                &tenant_a,
                &retention_signer.public_key(),
                &terminal_checkpoint,
            )
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    store.set_tenant_enabled(&tenant_a, false).await?;
    assert!(matches!(
        store.get_job(&tenant_a, "job-1").await,
        Err(HostedMarketStoreError::TenantDisabled)
    ));
    Ok(())
}

fn signed_domain_payload(
    event_kind: HostedMarketDomainEventKind,
    signer: &Keypair,
    body: serde_json::Value,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if event_kind != HostedMarketDomainEventKind::FindingPublished {
        return Err(std::io::Error::other("integration helper only builds findings").into());
    }
    let marker = sha256_hex(&canonical_json_bytes(&body)?);
    let mut finding = Finding {
        schema: FINDING_SCHEMA_V1.to_owned(),
        finding_id: String::new(),
        descriptor: FindingDescriptor {
            topic: format!("integration:{marker}"),
            context_sha256: marker.clone(),
            outcome_class: FindingOutcomeClass::PositiveResult,
        },
        guarantee_class: FindingGuaranteeClass::Asserted,
        payload_sha256: marker,
        payload_media_type: "application/json".to_owned(),
        evidence_receipt_ids: Vec::new(),
        evidence_checkpoint_ref: "integration-checkpoint".to_owned(),
        evidence_cost: MonetaryAmount {
            units: 1,
            currency: "USD".to_owned(),
        },
        runtime_assurance_tier: None,
        evidence_class: FindingEvidenceClass::Asserted,
        replay_recipe_sha256: None,
        intent_commitment_receipt_id: None,
        bond_ref: "integration-bond".to_owned(),
        status_feed_ref: "integration-status".to_owned(),
        license_ref: None,
        price_hint_ref: None,
        issuer: signer.public_key(),
        issued_at: 1_700_000_000,
        expires_at: 1_900_000_000,
        signature: String::new(),
    };
    finding.finding_id = compute_finding_id(&finding)?;
    Ok(canonical_json_bytes(&sign_finding(finding, signer)?)?)
}

fn signed_principal_replication_event(
    tenant: &HostedTenantId,
    sequence: u64,
    lifecycle_event: SignedExportEnvelope<HostedPrincipalLifecycleBody>,
    source_signer: &Keypair,
) -> Result<SignedExportEnvelope<HostedPrincipalReplicationEventBody>, Box<dyn Error>> {
    let committed_at = lifecycle_event.body.created_at;
    Ok(SignedExportEnvelope::sign(
        HostedPrincipalReplicationEventBody {
            schema: HOSTED_PRINCIPAL_REPLICATION_EVENT_SCHEMA.to_owned(),
            tenant_id: tenant.as_str().to_owned(),
            source_authority: HostedMarketAuthority::Sqlite,
            authority_epoch: 1,
            sequence,
            lifecycle_event,
            committed_at,
        },
        source_signer,
    )?)
}

async fn append_replication_check(
    replicator: &PostgresFindingMarketReplicator,
    tenant: &HostedTenantId,
    signer: &Keypair,
    spec: ReplicationCheckSpec<'_>,
) -> Result<(), Box<dyn Error>> {
    let check = SignedExportEnvelope::sign(
        HostedReplicationCheckBody {
            schema: HOSTED_REPLICATION_CHECK_SCHEMA.to_owned(),
            tenant_id: tenant.as_str().to_owned(),
            source_authority: spec.source_authority,
            authority_epoch: spec.authority_epoch,
            through_sequence: spec.through_sequence,
            source_projection_sha256: spec.projection_sha256.to_owned(),
            target_projection_sha256: spec.projection_sha256.to_owned(),
            lag_seconds: 0,
            projection_difference_count: 0,
            security_counter_count: 0,
            checked_at: spec.checked_at,
        },
        signer,
    )?;
    assert_eq!(
        replicator
            .append_replication_check(tenant, &signer.public_key(), &check)
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    Ok(())
}

struct ReplicationCheckSpec<'a> {
    authority_epoch: u64,
    through_sequence: u64,
    projection_sha256: &'a str,
    source_authority: HostedMarketAuthority,
    checked_at: u64,
}

#[allow(clippy::too_many_arguments)]
async fn apply_authority_transition(
    replicator: &PostgresFindingMarketReplicator,
    tenant: &HostedTenantId,
    signer: &Keypair,
    operation: HostedAuthorityTransitionOperation,
    from_authority: HostedMarketAuthority,
    to_authority: HostedMarketAuthority,
    from_epoch: u64,
    to_epoch: u64,
    through_sequence: u64,
    checkpoint_sha256: &str,
    rollback_window_ends_at: Option<u64>,
    created_at: u64,
) -> Result<(), Box<dyn Error>> {
    let transition = SignedExportEnvelope::sign(
        HostedAuthorityTransitionBody {
            schema: HOSTED_AUTHORITY_TRANSITION_SCHEMA.to_owned(),
            tenant_id: tenant.as_str().to_owned(),
            operation,
            from_authority,
            to_authority,
            from_epoch,
            to_epoch,
            through_sequence,
            source_checkpoint_sha256: checkpoint_sha256.to_owned(),
            target_checkpoint_sha256: checkpoint_sha256.to_owned(),
            configuration_revision: "integration-revision-1".to_owned(),
            rollback_window_ends_at,
            created_at,
        },
        signer,
    )?;
    assert_eq!(
        replicator
            .apply_authority_transition(tenant, &signer.public_key(), &transition)
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    Ok(())
}

async fn install_legacy_migration_fixture(pool: &sqlx::PgPool) -> Result<(), Box<dyn Error>> {
    const LEGACY: &[(i64, &str, &str)] = &[
        (
            1,
            "hosted_market",
            include_str!("../migrations/0001_hosted_market.sql"),
        ),
        (
            2,
            "terminal_jobs",
            include_str!("../migrations/0002_terminal_jobs.sql"),
        ),
        (
            3,
            "lease_fencing",
            include_str!("../migrations/0003_lease_fencing.sql"),
        ),
        (
            4,
            "hosted_auth",
            include_str!("../migrations/0004_hosted_auth.sql"),
        ),
        (
            5,
            "market_aggregates",
            include_str!("../migrations/0005_market_aggregates.sql"),
        ),
        (
            6,
            "tenant_registry_rls",
            include_str!("../migrations/0006_tenant_registry_rls.sql"),
        ),
        (
            7,
            "tenant_limits",
            include_str!("../migrations/0007_tenant_limits.sql"),
        ),
        (
            8,
            "append_only_aggregates",
            include_str!("../migrations/0008_append_only_aggregates.sql"),
        ),
        (
            9,
            "aggregate_checkpoints",
            include_str!("../migrations/0009_aggregate_checkpoints.sql"),
        ),
    ];
    sqlx::raw_sql(
        r#"CREATE TABLE chio_finding_market_schema_migrations (
            version BIGINT PRIMARY KEY CHECK (version > 0),
            name TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 128),
            checksum_sha256 CHAR(64) NOT NULL CHECK (
                checksum_sha256 !~ '[^0-9a-f]'
            ),
            applied_at BIGINT NOT NULL CHECK (applied_at > 0)
        )"#,
    )
    .execute(pool)
    .await?;
    for (version, name, sql) in LEGACY {
        let mut transaction = pool.begin().await?;
        sqlx::raw_sql(sql).execute(&mut *transaction).await?;
        sqlx::query(
            "INSERT INTO chio_finding_market_schema_migrations (version, name, checksum_sha256, applied_at) VALUES ($1, $2, $3, floor(extract(epoch from clock_timestamp()))::bigint)",
        )
        .bind(version)
        .bind(name)
        .bind(sha256_hex(sql.as_bytes()))
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
    }
    Ok(())
}
