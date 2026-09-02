use std::collections::BTreeSet;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::{canonical_json_bytes, sha256_hex};
use chio_finding::{
    compute_finding_id, sign_finding, Finding, FindingDescriptor, FindingEvidenceClass,
    FindingGuaranteeClass, FindingOutcomeClass, FINDING_SCHEMA_V1,
};
use chio_finding_market_store_postgres::{
    HostedAggregateCheckpointBody, HostedAggregateKind, HostedArchiveManifestBody,
    HostedAuthorityTransitionBody, HostedAuthorityTransitionOperation,
    HostedCapabilityAdmissionOutcome, HostedDomainWrite, HostedGcReceiptBody, HostedJobState,
    HostedJobWriteOutcome, HostedJournalCheckpointBody, HostedLegalHoldAction, HostedLegalHoldBody,
    HostedMarketAuthority, HostedMarketDomainArtifact, HostedMarketDomainEvent,
    HostedMarketDomainEventKind, HostedMarketStoreError, HostedPrincipalLifecycleBody,
    HostedPrincipalLifecycleOperation, HostedPrincipalReplicationEventBody, HostedPrincipalRole,
    HostedReplicationCheckBody, HostedReplicationEventBody, HostedRestoreVerificationBody,
    HostedRetentionResourceKind, HostedRetentionTarget, HostedRollbackOutboxEntry, HostedTenantId,
    HostedTenantLimits, PostgresFindingMarketMigrator, PostgresFindingMarketReplicator,
    PostgresFindingMarketRetention, PostgresFindingMarketStore, HOSTED_AGGREGATE_CHECKPOINT_SCHEMA,
    HOSTED_ARCHIVE_MANIFEST_SCHEMA, HOSTED_AUTHORITY_TRANSITION_SCHEMA, HOSTED_GC_RECEIPT_SCHEMA,
    HOSTED_JOURNAL_CHECKPOINT_SCHEMA, HOSTED_LEGAL_HOLD_SCHEMA, HOSTED_PRINCIPAL_LIFECYCLE_SCHEMA,
    HOSTED_PRINCIPAL_REPLICATION_EVENT_SCHEMA, HOSTED_REPLICATION_CHECK_SCHEMA,
    HOSTED_REPLICATION_EVENT_SCHEMA, HOSTED_RESTORE_VERIFICATION_SCHEMA,
};
use sqlx::Row as _;

mod support;

use support::{
    append_replication_check, apply_authority_transition,
    assert_admission_and_accounting_invariants, assert_admission_binds_its_request,
    assert_atomic_purchase_recovery, assert_catalog_retractions,
    assert_concurrent_duplicates_replay, assert_disabled_tenant_blocks_worker_transitions,
    assert_forged_job_digest_rejected, assert_legacy_delivery_upgrade_rejects,
    assert_multi_replica_leases_and_shutdown_refunds, assert_paged_aggregate_history,
    assert_prior_release_writes_keep_accumulators, assert_tenant_disablement_serializes,
    assert_terminal_job_retention_gc, assert_worker_job_boundary, migrate_legacy_fixture,
    signed_domain_payload, signed_principal_replication_event, ReplicationCheckSpec,
};

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
    migrate_legacy_fixture(&admin_pool, &migrator_url).await?;
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
            chio_finding_market_dpop_nonces, chio_finding_market_dpop_admission_state,
            chio_finding_market_capability_uses,
            chio_finding_market_capability_request_admissions,
            chio_finding_market_security_events, chio_finding_market_aggregate_events,
            chio_finding_market_aggregate_heads,
            chio_finding_market_aggregate_checkpoints,
            chio_finding_market_spend_reservations,
            chio_finding_market_spend_periods,
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
        GRANT SELECT, INSERT, UPDATE ON chio_finding_market_dpop_admission_state TO chio_market_runtime_test;
        GRANT SELECT, INSERT, UPDATE, DELETE ON chio_finding_market_capability_uses TO chio_market_runtime_test;
        GRANT SELECT, INSERT, DELETE ON chio_finding_market_capability_request_admissions TO chio_market_runtime_test;
        GRANT SELECT, INSERT ON chio_finding_market_security_events TO chio_market_runtime_test;
        GRANT SELECT ON chio_finding_market_aggregate_events TO chio_market_runtime_test;
        GRANT SELECT ON chio_finding_market_aggregate_heads TO chio_market_runtime_test;
        GRANT SELECT, INSERT ON chio_finding_market_aggregate_checkpoints TO chio_market_runtime_test;
        GRANT SELECT, INSERT, UPDATE ON chio_finding_market_spend_reservations TO chio_market_runtime_test;
        GRANT SELECT ON chio_finding_market_spend_periods TO chio_market_runtime_test;
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
        GRANT EXECUTE ON FUNCTION chio_finding_market_claim_jobs(TEXT, TEXT, BIGINT, BIGINT),
            chio_finding_market_renew_job_lease(TEXT, TEXT, TEXT, BIGINT, BIGINT),
            chio_finding_market_complete_job(TEXT, TEXT, TEXT, BIGINT, TEXT, BYTEA),
            chio_finding_market_fail_job(TEXT, TEXT, TEXT, BIGINT, TEXT, BIGINT),
            chio_finding_market_relinquish_job_lease(TEXT, TEXT, TEXT, BIGINT),
            chio_finding_market_exhaust_job(TEXT, TEXT, TEXT, BIGINT, TEXT)
            TO chio_market_runtime_test;
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
        GRANT SELECT ON chio_finding_market_jobs TO chio_market_worker_test;
        GRANT EXECUTE ON FUNCTION chio_finding_market_claim_jobs(TEXT, TEXT, BIGINT, BIGINT),
            chio_finding_market_renew_job_lease(TEXT, TEXT, TEXT, BIGINT, BIGINT),
            chio_finding_market_complete_job(TEXT, TEXT, TEXT, BIGINT, TEXT, BYTEA),
            chio_finding_market_fail_job(TEXT, TEXT, TEXT, BIGINT, TEXT, BIGINT),
            chio_finding_market_relinquish_job_lease(TEXT, TEXT, TEXT, BIGINT),
            chio_finding_market_exhaust_job(TEXT, TEXT, TEXT, BIGINT, TEXT)
            TO chio_market_worker_test;
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
    let worker_store =
        PostgresFindingMarketStore::from_pool_for_integration_tests(worker_pool.clone(), 8);
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
    let concurrency_tenant = HostedTenantId::new(format!("integration-concurrency-{nonce}"))?;
    let tenant_limits = HostedTenantLimits::new(1, 8, 10_000, "integration-revision-1")?;
    store
        .register_tenant(&tenant_a, &tenant_limits, 1_700_000_000)
        .await?;
    store
        .register_tenant(&tenant_b, &tenant_limits, 1_700_000_000)
        .await?;
    store
        .register_tenant(
            &concurrency_tenant,
            &HostedTenantLimits::new(3, 8, 10_000, "integration-concurrency-revision-1")?,
            1_700_000_000,
        )
        .await?;
    assert_legacy_delivery_upgrade_rejects(&admin_pool, &tenant_a).await?;
    assert_worker_job_boundary(&worker_pool, &tenant_a).await?;
    assert_tenant_disablement_serializes(&store, &runtime_pool, &tenant_a).await?;
    assert_disabled_tenant_blocks_worker_transitions(&store, &worker_pool, nonce).await?;
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
            .reserve_monthly_spend(&tenant_a, "purchase-spend-1", 6_000)
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    assert_eq!(
        store
            .reserve_monthly_spend(&tenant_a, "purchase-spend-1", 6_000)
            .await?,
        HostedJobWriteOutcome::ExactReplay
    );
    assert!(matches!(
        store
            .reserve_monthly_spend(&tenant_a, "purchase-spend-2", 4_001)
            .await,
        Err(HostedMarketStoreError::Capacity)
    ));
    assert_eq!(
        store
            .commit_monthly_spend(&tenant_a, "purchase-spend-1")
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    assert_eq!(
        store
            .commit_monthly_spend(&tenant_a, "purchase-spend-1")
            .await?,
        HostedJobWriteOutcome::ExactReplay
    );
    assert!(matches!(
        store
            .reserve_monthly_spend(&tenant_a, "purchase-spend-1", 6_000)
            .await,
        Err(HostedMarketStoreError::Conflict)
    ));
    assert!(matches!(
        store
            .release_monthly_spend(&tenant_a, "purchase-spend-1")
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
    let period_from_database_timestamp: String = sqlx::query_scalar(
        "SELECT to_char(to_timestamp($1::double precision) AT TIME ZONE 'UTC', 'YYYY-MM')",
    )
    .bind(i64::try_from(committed_spend.created_at)?)
    .fetch_one(&admin_pool)
    .await?;
    assert_eq!(
        committed_spend.billing_period,
        period_from_database_timestamp
    );
    let database_now: i64 =
        sqlx::query_scalar("SELECT FLOOR(EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::BIGINT")
            .fetch_one(&admin_pool)
            .await?;
    assert!(committed_spend.created_at <= u64::try_from(database_now)?);
    assert!(committed_spend.updated_at >= committed_spend.created_at);
    assert!(store
        .monthly_spend_reservation(&tenant_b, "purchase-spend-1")
        .await?
        .is_none());
    store
        .reserve_monthly_spend(&tenant_a, "purchase-spend-release", 4_000)
        .await?;
    assert_eq!(
        store
            .release_monthly_spend(&tenant_a, "purchase-spend-release")
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    assert_eq!(
        store
            .release_monthly_spend(&tenant_a, "purchase-spend-release")
            .await?,
        HostedJobWriteOutcome::ExactReplay
    );
    assert_eq!(
        store
            .reserve_monthly_spend(&tenant_a, "purchase-spend-after-release", 4_000,)
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
    let mismatched_replication = SignedExportEnvelope::sign(
        HostedReplicationEventBody {
            schema: HOSTED_REPLICATION_EVENT_SCHEMA.to_owned(),
            tenant_id: tenant_a.as_str().to_owned(),
            source_authority: HostedMarketAuthority::Sqlite,
            authority_epoch: 1,
            sequence: 3,
            event_kind: HostedMarketDomainEventKind::PenaltyAssessed,
            aggregate_id: "mismatched-penalty".to_owned(),
            event_id: "mismatched-penalty-event".to_owned(),
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
                &mismatched_replication,
            )
            .await,
        Err(HostedMarketStoreError::Invalid("market penalty authority"))
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
    let catalog = store.catalog_findings(&tenant_a, None, 10).await?;
    assert_eq!(catalog.items.len(), 1);
    assert_eq!(catalog.items[0].aggregate_id, market_finding_id);
    assert!(catalog.next_cursor.is_none());
    assert!(store
        .catalog_findings(&tenant_b, None, 10)
        .await?
        .items
        .is_empty());
    assert!(matches!(
        store.catalog_findings(&tenant_a, None, 0).await,
        Err(HostedMarketStoreError::Invalid("catalog limit"))
    ));
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
    assert_eq!(
        store
            .publish_finding(
                &tenant_a,
                &market_finding,
                &HostedDomainWrite::new("challenge-a-submitted", 0, None, 1_700_000_001,)?,
            )
            .await?,
        HostedJobWriteOutcome::ExactReplay
    );
    let advanced_event = HostedMarketDomainEvent::from_artifact(
        market_finding_id.clone(),
        "challenge-a-evaluating",
        &market_artifact,
    )?;
    assert_eq!(
        store
            .append_domain_event(
                &tenant_a,
                &advanced_event,
                head.revision,
                Some(&head.event_sha256),
                authority_now,
            )
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    assert_eq!(
        store
            .append_domain_event(
                &tenant_a,
                &advanced_event,
                head.revision,
                Some(&head.event_sha256),
                authority_now,
            )
            .await?,
        HostedJobWriteOutcome::ExactReplay,
        "an exact response-loss retry must bypass the newly stale replication gate"
    );
    assert_eq!(
        store
            .append_domain_event(
                &tenant_a,
                &advanced_event,
                head.revision,
                Some(&head.event_sha256),
                1_900_000_001,
            )
            .await?,
        HostedJobWriteOutcome::ExactReplay,
        "server-owned retry time must not change the idempotent event identity"
    );
    let expired_payload = signed_domain_payload(
        HostedMarketDomainEventKind::FindingPublished,
        &domain_signer,
        serde_json::json!({"findingId": "expired-fresh-publication"}),
    )?;
    let expired_finding: Finding = serde_json::from_slice(&expired_payload)?;
    let expired_finding_id = expired_finding.finding_id.clone();
    let expired_event = HostedMarketDomainEvent::from_artifact(
        &expired_finding_id,
        "expired-fresh-publication",
        &HostedMarketDomainArtifact::Finding(expired_finding),
    )?;
    assert!(matches!(
        store
            .append_domain_event(&tenant_a, &expired_event, 0, None, 1_900_000_001)
            .await,
        Err(HostedMarketStoreError::Invalid(
            "finding artifact freshness"
        ))
    ));
    let advanced_projection_revision: i64 = sqlx::query_scalar(
        "SELECT revision FROM chio_finding_market_domain_projections WHERE tenant_id = $1 AND aggregate_kind = 'finding' AND aggregate_id = $2",
    )
    .bind(tenant_a.as_str())
    .bind(&market_finding_id)
    .fetch_one(&admin_pool)
    .await?;
    assert_eq!(advanced_projection_revision, 2);
    let projection_tamper = sqlx::query(
        "UPDATE chio_finding_market_domain_projections SET updated_at = updated_at + 1 WHERE tenant_id = $1 AND aggregate_kind = 'finding' AND aggregate_id = $2",
    )
    .bind(tenant_a.as_str())
    .bind(&market_finding_id)
    .execute(&admin_pool)
    .await;
    assert!(projection_tamper.is_err());
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
    assert_eq!(
        store
            .apply_principal_lifecycle(
                &tenant_a,
                &operator_signer.public_key(),
                &post_cutover_rotation,
            )
            .await?,
        HostedJobWriteOutcome::ExactReplay,
        "an exact principal response-loss retry must bypass the newly stale replication gate"
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
    assert_atomic_purchase_recovery(
        &store,
        &tenant_a,
        &domain_signer,
        &market_finding_id,
        &replicator,
        &source_signer,
        authority_now,
    )
    .await?;
    assert_catalog_retractions(
        &store,
        &tenant_a,
        &tenant_b,
        &domain_signer,
        &market_finding_id,
        &replicator,
        &source_signer,
        authority_now,
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
    assert_paged_aggregate_history(&store, &tenant_a, &market_finding_id).await?;

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
        &HostedMarketDomainArtifact::Finding(archive_finding.clone()),
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
    let release_a = SignedExportEnvelope::sign(
        HostedLegalHoldBody {
            schema: HOSTED_LEGAL_HOLD_SCHEMA.to_owned(),
            tenant_id: tenant_a.as_str().to_owned(),
            hold_id: "legal-hold-a".to_owned(),
            target: target.clone(),
            action: HostedLegalHoldAction::Released,
            previous_hold_event_sha256: Some(hold_sha256.clone()),
            created_at: authority_now + 5,
        },
        &retention_signer,
    )?;
    let release_b = SignedExportEnvelope::sign(
        HostedLegalHoldBody {
            schema: HOSTED_LEGAL_HOLD_SCHEMA.to_owned(),
            tenant_id: tenant_a.as_str().to_owned(),
            hold_id: "legal-hold-a".to_owned(),
            target: target.clone(),
            action: HostedLegalHoldAction::Released,
            previous_hold_event_sha256: Some(hold_sha256),
            created_at: authority_now + 6,
        },
        &retention_signer,
    )?;
    let retention_public_key = retention_signer.public_key();
    let (release_a_result, release_b_result) = tokio::join!(
        retention.append_legal_hold(&tenant_a, &retention_public_key, &release_a),
        retention.append_legal_hold(&tenant_a, &retention_public_key, &release_b),
    );
    assert!(matches!(
        (release_a_result, release_b_result),
        (
            Ok(HostedJobWriteOutcome::Inserted),
            Err(HostedMarketStoreError::Conflict)
        ) | (
            Err(HostedMarketStoreError::Conflict),
            Ok(HostedJobWriteOutcome::Inserted)
        )
    ));

    let advanced_archive_event = HostedMarketDomainEvent::from_artifact(
        archive_finding_id.clone(),
        "archive-finding-a-republished",
        &HostedMarketDomainArtifact::Finding(archive_finding),
    )?;
    let archive_projection_sha256 = replicator.target_projection_sha256(&tenant_a).await?;
    let archive_outbox_sequence = store.authority_state(&tenant_a).await?.last_outbox_sequence;
    append_replication_check(
        &replicator,
        &tenant_a,
        &source_signer,
        ReplicationCheckSpec {
            authority_epoch: 3,
            through_sequence: archive_outbox_sequence,
            projection_sha256: &archive_projection_sha256,
            source_authority: HostedMarketAuthority::Postgres,
            checked_at: authority_now + 7,
        },
    )
    .await?;
    assert_eq!(
        store
            .append_domain_event(
                &tenant_a,
                &advanced_archive_event,
                archive_head.revision,
                Some(&archive_head.event_sha256),
                authority_now + 7,
            )
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    let stale_gc_receipt = SignedExportEnvelope::sign(
        HostedGcReceiptBody {
            schema: HOSTED_GC_RECEIPT_SCHEMA.to_owned(),
            tenant_id: tenant_a.as_str().to_owned(),
            archive_sha256: archive_sha256.clone(),
            target: target.clone(),
            completed_at: authority_now + 8,
        },
        &retention_signer,
    )?;
    assert!(matches!(
        retention
            .garbage_collect(&tenant_a, &retention_public_key, &stale_gc_receipt)
            .await,
        Err(HostedMarketStoreError::Conflict)
    ));
    let advanced_archive_head = store
        .aggregate_head(&tenant_a, HostedAggregateKind::Finding, &archive_finding_id)
        .await?
        .ok_or("advanced archive aggregate head missing")?;
    assert_eq!(advanced_archive_head.revision, archive_head.revision + 1);

    let advanced_commitment = retention.journal_commitment(&tenant_a).await?;
    let advanced_checkpoint = SignedExportEnvelope::sign(
        HostedJournalCheckpointBody {
            schema: HOSTED_JOURNAL_CHECKPOINT_SCHEMA.to_owned(),
            tenant_id: tenant_a.as_str().to_owned(),
            aggregate_heads_sha256: advanced_commitment.aggregate_heads_sha256,
            terminal_jobs_sha256: advanced_commitment.terminal_jobs_sha256,
            previous_checkpoint_sha256: advanced_commitment.previous_checkpoint_sha256,
            migration_version: advanced_commitment.migration_version,
            configuration_revision: "integration-revision-1".to_owned(),
            created_at: authority_now + 9,
        },
        &retention_signer,
    )?;
    retention
        .append_journal_checkpoint(&tenant_a, &retention_public_key, &advanced_checkpoint)
        .await?;
    let advanced_checkpoint_sha256 = sha256_hex(&canonical_json_bytes(&advanced_checkpoint)?);
    let advanced_target = HostedRetentionTarget {
        resource_kind: HostedRetentionResourceKind::Aggregate,
        resource_family: "finding".to_owned(),
        resource_id: archive_finding_id.clone(),
        resource_revision: advanced_archive_head.revision,
        resource_sha256: advanced_archive_head.event_sha256.clone(),
    };
    let advanced_manifest_body = HostedArchiveManifestBody {
        schema: HOSTED_ARCHIVE_MANIFEST_SCHEMA.to_owned(),
        tenant_id: tenant_a.as_str().to_owned(),
        target: advanced_target.clone(),
        covered_checkpoint_sha256: advanced_checkpoint_sha256,
        object_uri: "s3://chio-test/archive-finding-a-v2-a.json".to_owned(),
        object_sha256: "b".repeat(64),
        object_size: 256,
        configuration_revision: "integration-revision-1".to_owned(),
        previous_archive_sha256: Some(archive_sha256),
        created_at: authority_now + 10,
    };
    let advanced_manifest_a =
        SignedExportEnvelope::sign(advanced_manifest_body.clone(), &retention_signer)?;
    let advanced_manifest_b = SignedExportEnvelope::sign(
        HostedArchiveManifestBody {
            object_uri: "s3://chio-test/archive-finding-a-v2-b.json".to_owned(),
            object_sha256: "c".repeat(64),
            created_at: authority_now + 11,
            ..advanced_manifest_body
        },
        &retention_signer,
    )?;
    let (manifest_a_result, manifest_b_result) = tokio::join!(
        retention.append_archive_manifest(&tenant_a, &retention_public_key, &advanced_manifest_a,),
        retention.append_archive_manifest(&tenant_a, &retention_public_key, &advanced_manifest_b,),
    );
    let manifest_a_inserted = matches!(&manifest_a_result, Ok(HostedJobWriteOutcome::Inserted));
    let manifest_b_inserted = matches!(&manifest_b_result, Ok(HostedJobWriteOutcome::Inserted));
    assert!(
        (manifest_a_inserted && matches!(manifest_b_result, Err(HostedMarketStoreError::Conflict)))
            || (manifest_b_inserted
                && matches!(manifest_a_result, Err(HostedMarketStoreError::Conflict)))
    );
    let retained_advanced_manifest = if manifest_a_inserted {
        &advanced_manifest_a
    } else {
        &advanced_manifest_b
    };
    let advanced_archive_sha256 = sha256_hex(&canonical_json_bytes(retained_advanced_manifest)?);
    let advanced_restore = SignedExportEnvelope::sign(
        HostedRestoreVerificationBody {
            schema: HOSTED_RESTORE_VERIFICATION_SCHEMA.to_owned(),
            tenant_id: tenant_a.as_str().to_owned(),
            archive_sha256: advanced_archive_sha256.clone(),
            restored_resource_sha256: advanced_target.resource_sha256.clone(),
            verified_at: authority_now + 12,
        },
        &retention_signer,
    )?;
    retention
        .append_restore_verification(&tenant_a, &retention_public_key, &advanced_restore)
        .await?;
    let gc_receipt = SignedExportEnvelope::sign(
        HostedGcReceiptBody {
            schema: HOSTED_GC_RECEIPT_SCHEMA.to_owned(),
            tenant_id: tenant_a.as_str().to_owned(),
            archive_sha256: advanced_archive_sha256,
            target: advanced_target.clone(),
            completed_at: authority_now + 13,
        },
        &retention_signer,
    )?;
    assert_eq!(
        retention
            .garbage_collect(&tenant_a, &retention_public_key, &gc_receipt)
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    assert!(store
        .aggregate_head(&tenant_a, HostedAggregateKind::Finding, &archive_finding_id,)
        .await?
        .is_none());
    let retained_projection: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chio_finding_market_domain_projections WHERE tenant_id = $1 AND aggregate_kind = 'finding' AND aggregate_id = $2",
    )
    .bind(tenant_a.as_str())
    .bind(&archive_finding_id)
    .fetch_one(&admin_pool)
    .await?;
    assert_eq!(retained_projection, 0);
    let post_gc_projection_sha256 = replicator.target_projection_sha256(&tenant_a).await?;
    let post_gc_outbox_sequence = store.authority_state(&tenant_a).await?.last_outbox_sequence;
    append_replication_check(
        &replicator,
        &tenant_a,
        &source_signer,
        ReplicationCheckSpec {
            authority_epoch: 3,
            through_sequence: post_gc_outbox_sequence,
            projection_sha256: &post_gc_projection_sha256,
            source_authority: HostedMarketAuthority::Postgres,
            checked_at: authority_now + 14,
        },
    )
    .await?;
    let resurrected_finding: Finding = serde_json::from_slice(&archive_payload)?;
    let resurrected_event = HostedMarketDomainEvent::from_artifact(
        archive_finding_id.clone(),
        "archive-finding-a-after-gc",
        &HostedMarketDomainArtifact::Finding(resurrected_finding),
    )?;
    assert!(matches!(
        store
            .append_domain_event(&tenant_a, &resurrected_event, 0, None, authority_now + 14,)
            .await,
        Err(HostedMarketStoreError::Conflict)
    ));
    let post_gc_hold = SignedExportEnvelope::sign(
        HostedLegalHoldBody {
            schema: HOSTED_LEGAL_HOLD_SCHEMA.to_owned(),
            tenant_id: tenant_a.as_str().to_owned(),
            hold_id: "legal-hold-after-gc".to_owned(),
            target: advanced_target,
            action: HostedLegalHoldAction::Placed,
            previous_hold_event_sha256: None,
            created_at: authority_now + 15,
        },
        &retention_signer,
    )?;
    assert!(matches!(
        retention
            .append_legal_hold(&tenant_a, &retention_public_key, &post_gc_hold)
            .await,
        Err(HostedMarketStoreError::Conflict)
    ));

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
    let first_nonce = "d".repeat(64);
    let second_nonce = "e".repeat(64);
    let first_binding = "4".repeat(64);
    let second_binding = "5".repeat(64);
    let (first_admission, second_admission) = tokio::join!(
        store.consume_capability_dpop_admission(
            &tenant_a,
            "capability-atomic",
            &first_nonce,
            Some(&first_binding),
            1_700_000_300,
            2,
            1_700_000_300,
            1_700_000_001,
            8,
        ),
        store.consume_capability_dpop_admission(
            &tenant_a,
            "capability-atomic",
            &second_nonce,
            Some(&second_binding),
            1_700_000_300,
            2,
            1_700_000_300,
            1_700_000_002,
            8,
        ),
    );
    assert_eq!(first_admission?, HostedCapabilityAdmissionOutcome::Admitted);
    assert_eq!(
        second_admission?,
        HostedCapabilityAdmissionOutcome::Admitted
    );
    assert_eq!(
        store
            .consume_capability_dpop_admission(
                &tenant_a,
                "capability-atomic",
                &"f".repeat(64),
                Some(&"c".repeat(64)),
                1_700_000_300,
                2,
                1_700_000_300,
                1_700_000_003,
                8,
            )
            .await?,
        HostedCapabilityAdmissionOutcome::BudgetExceeded
    );
    assert_eq!(
        store
            .consume_capability_dpop_admission(
                &tenant_a,
                "capability-atomic",
                &"d".repeat(64),
                Some(&"a".repeat(64)),
                1_700_000_300,
                2,
                1_700_000_300,
                1_700_000_004,
                8,
            )
            .await?,
        HostedCapabilityAdmissionOutcome::Replay
    );
    assert_admission_binds_its_request(&store, &tenant_a, &first_nonce, &first_binding).await?;

    let rejected_nonce_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chio_finding_market_dpop_nonces WHERE tenant_id = $1 AND capability_id = $2 AND nonce_sha256 = $3",
    )
    .bind(tenant_a.as_str())
    .bind("capability-atomic")
    .bind("f".repeat(64))
    .fetch_one(&admin_pool)
    .await?;
    assert_eq!(rejected_nonce_count, 0);

    assert_concurrent_duplicates_replay(&store, nonce).await?;
    assert_prior_release_writes_keep_accumulators(&store, &runtime_pool, nonce).await?;
    assert_admission_and_accounting_invariants(&store, &runtime_pool, &admin_pool, nonce).await?;

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
    assert!(store
        .claim_due_jobs(&tenant_a, "worker-b", 10, 2)
        .await?
        .is_empty());
    assert!(store
        .claim_due_jobs(&tenant_a, "worker-b", 10, 1)
        .await?
        .is_empty());

    assert_multi_replica_leases_and_shutdown_refunds(&store, &admin_pool, &concurrency_tenant)
        .await?;
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
    assert_forged_job_digest_rejected(&worker_pool, &tenant_a, "job-1", &recovered_lease, result)
        .await?;
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
    assert_terminal_job_retention_gc(
        &retention,
        &admin_pool,
        &store,
        &tenant_a,
        &retention_signer,
        &retention_public_key,
        authority_now,
        &request,
        payload_a,
    )
    .await?;
    store.set_tenant_enabled(&tenant_a, false).await?;
    assert!(matches!(
        store.get_job(&tenant_a, "job-1").await,
        Err(HostedMarketStoreError::TenantDisabled)
    ));
    Ok(())
}
