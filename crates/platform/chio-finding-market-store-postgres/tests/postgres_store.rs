use std::collections::BTreeSet;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::sha256_hex;
use chio_finding_market_store_postgres::{
    HostedAggregateCheckpointBody, HostedAggregateKind, HostedJobState, HostedJobWriteOutcome,
    HostedMarketStoreError, HostedTenantId, HostedTenantLimits, PostgresFindingMarketMigrator,
    PostgresFindingMarketStore, HOSTED_AGGREGATE_CHECKPOINT_SCHEMA,
};
use sqlx::Row as _;

#[tokio::test]
async fn tenant_isolation_exact_replay_and_lease_recovery() -> Result<(), Box<dyn Error>> {
    let database_url = std::env::var("CHIO_TEST_POSTGRES_URL")?;
    let migrator_url = std::env::var("CHIO_TEST_POSTGRES_MIGRATOR_URL")?;
    let runtime_url = std::env::var("CHIO_TEST_POSTGRES_RUNTIME_URL")?;
    let admin_pool = sqlx::PgPool::connect(&database_url).await?;
    sqlx::raw_sql(
        r#"
        DO $role$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chio_market_migrator_test') THEN
                CREATE ROLE chio_market_migrator_test LOGIN PASSWORD 'test-only-password'
                    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
            END IF;
            ALTER ROLE chio_market_migrator_test LOGIN PASSWORD 'test-only-password'
                NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
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
    let migrator_pool = sqlx::PgPool::connect(&migrator_url).await?;
    let migrator = PostgresFindingMarketMigrator::from_pool_for_integration_tests(migrator_pool);
    migrator.migrate().await?;
    migrator.migrate().await?;
    let migration_ledger_tamper =
        sqlx::query("DELETE FROM chio_finding_market_schema_migrations WHERE version = 1")
            .execute(&admin_pool)
            .await;
    assert!(migration_ledger_tamper.is_err());
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
        GRANT SELECT ON chio_finding_market_schema_migrations TO chio_market_runtime_test;
        REVOKE ALL ON chio_finding_market_tenants, chio_finding_market_jobs,
            chio_finding_market_principals, chio_finding_market_api_keys,
            chio_finding_market_dpop_nonces, chio_finding_market_capability_uses,
            chio_finding_market_security_events, chio_finding_market_aggregate_events,
            chio_finding_market_aggregate_heads,
            chio_finding_market_aggregate_checkpoints,
            chio_finding_market_spend_reservations
            FROM chio_market_runtime_test;
        GRANT SELECT, INSERT, UPDATE ON chio_finding_market_tenants TO chio_market_runtime_test;
        GRANT SELECT, INSERT, UPDATE ON chio_finding_market_jobs TO chio_market_runtime_test;
        GRANT SELECT, INSERT ON chio_finding_market_principals TO chio_market_runtime_test;
        GRANT SELECT, INSERT, UPDATE ON chio_finding_market_api_keys TO chio_market_runtime_test;
        GRANT SELECT, INSERT, DELETE ON chio_finding_market_dpop_nonces TO chio_market_runtime_test;
        GRANT SELECT, INSERT, UPDATE, DELETE ON chio_finding_market_capability_uses TO chio_market_runtime_test;
        GRANT SELECT, INSERT ON chio_finding_market_security_events TO chio_market_runtime_test;
        GRANT SELECT ON chio_finding_market_aggregate_events TO chio_market_runtime_test;
        GRANT SELECT ON chio_finding_market_aggregate_heads TO chio_market_runtime_test;
        GRANT SELECT, INSERT ON chio_finding_market_aggregate_checkpoints TO chio_market_runtime_test;
        GRANT SELECT, INSERT, UPDATE ON chio_finding_market_spend_reservations TO chio_market_runtime_test;
        GRANT EXECUTE ON FUNCTION chio_finding_market_append_aggregate_event(
            TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, TEXT, TEXT, BYTEA, TEXT, BIGINT
        ) TO chio_market_runtime_test;
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

    store
        .put_principal(
            &tenant_a,
            "buyer-a",
            chio_finding_market_store_postgres::HostedPrincipalRole::Buyer,
            None,
            true,
            1_700_000_000,
        )
        .await?;
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

    let aggregate_payload = br#"{"challengeId":"challenge-a","state":"submitted"}"#;
    assert_eq!(
        store
            .append_aggregate_event(
                &tenant_a,
                HostedAggregateKind::Challenge,
                "challenge-a",
                "challenge-a-submitted",
                "challenge.submitted",
                0,
                None,
                aggregate_payload,
                1_700_000_001,
            )
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    assert_eq!(
        store
            .append_aggregate_event(
                &tenant_a,
                HostedAggregateKind::Challenge,
                "challenge-a",
                "challenge-a-submitted",
                "challenge.submitted",
                0,
                None,
                aggregate_payload,
                1_700_000_001,
            )
            .await?,
        HostedJobWriteOutcome::ExactReplay
    );
    let head = store
        .aggregate_head(&tenant_a, HostedAggregateKind::Challenge, "challenge-a")
        .await?
        .ok_or("aggregate head missing")?;
    assert_eq!(head.revision, 1);
    assert!(store
        .aggregate_head(&tenant_b, HostedAggregateKind::Challenge, "challenge-a")
        .await?
        .is_none());
    let advanced_payload = br#"{"challengeId":"challenge-a","state":"evaluating"}"#;
    store
        .append_aggregate_event(
            &tenant_a,
            HostedAggregateKind::Challenge,
            "challenge-a",
            "challenge-a-evaluating",
            "challenge.evaluating",
            head.revision,
            Some(&head.event_sha256),
            advanced_payload,
            1_700_000_002,
        )
        .await?;
    let history = store
        .aggregate_history(&tenant_a, HostedAggregateKind::Challenge, "challenge-a", 10)
        .await?;
    assert_eq!(history.len(), 2);
    assert_eq!(
        history[1].previous_event_sha256.as_deref(),
        Some(history[0].event_sha256.as_str())
    );
    assert!(matches!(
        store
            .aggregate_history(&tenant_a, HostedAggregateKind::Challenge, "challenge-a", 1)
            .await,
        Err(HostedMarketStoreError::Capacity)
    ));
    assert!(matches!(
        store
            .append_aggregate_event(
                &tenant_a,
                HostedAggregateKind::Challenge,
                "challenge-a",
                "challenge-a-stale",
                "challenge.stale",
                head.revision,
                Some(&head.event_sha256),
                advanced_payload,
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
            aggregate_kind: HostedAggregateKind::Challenge,
            aggregate_id: "challenge-a".to_owned(),
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
            HostedAggregateKind::Challenge,
            "challenge-a",
            &checkpoint_signer.public_key(),
        )
        .await?
        .ok_or("aggregate checkpoint missing")?;
    assert_eq!(retained_checkpoint.checkpoint, checkpoint);
    assert!(store
        .latest_aggregate_checkpoint(
            &tenant_b,
            HostedAggregateKind::Challenge,
            "challenge-a",
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
    store.set_tenant_enabled(&tenant_a, false).await?;
    assert!(matches!(
        store.get_job(&tenant_a, "job-1").await,
        Err(HostedMarketStoreError::TenantDisabled)
    ));
    Ok(())
}
