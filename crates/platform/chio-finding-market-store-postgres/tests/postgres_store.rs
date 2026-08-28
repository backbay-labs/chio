use std::collections::BTreeSet;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core_types::sha256_hex;
use chio_finding_market_store_postgres::{
    HostedJobState, HostedJobWriteOutcome, HostedMarketStoreError, HostedTenantId,
    PostgresFindingMarketStore,
};
use sqlx::Row as _;

#[tokio::test]
async fn tenant_isolation_exact_replay_and_lease_recovery() -> Result<(), Box<dyn Error>> {
    let database_url = std::env::var("CHIO_TEST_POSTGRES_URL")?;
    let runtime_url = std::env::var("CHIO_TEST_POSTGRES_RUNTIME_URL")?;
    let admin_pool = sqlx::PgPool::connect(&database_url).await?;
    let migrator =
        PostgresFindingMarketStore::from_pool_for_integration_tests(admin_pool.clone(), 8);
    migrator.migrate().await?;
    sqlx::raw_sql(
        r#"
        DO $role$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chio_market_runtime_test') THEN
                CREATE ROLE chio_market_runtime_test LOGIN PASSWORD 'test-only-password'
                    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
            END IF;
        END
        $role$;
        GRANT USAGE ON SCHEMA public TO chio_market_runtime_test;
        GRANT SELECT, INSERT, UPDATE, DELETE ON chio_finding_market_tenants TO chio_market_runtime_test;
        GRANT SELECT, INSERT, UPDATE, DELETE ON chio_finding_market_jobs TO chio_market_runtime_test;
        GRANT SELECT, INSERT, UPDATE, DELETE ON chio_finding_market_principals TO chio_market_runtime_test;
        GRANT SELECT, INSERT, UPDATE, DELETE ON chio_finding_market_api_keys TO chio_market_runtime_test;
        GRANT SELECT, INSERT, UPDATE, DELETE ON chio_finding_market_dpop_nonces TO chio_market_runtime_test;
        GRANT SELECT, INSERT, UPDATE, DELETE ON chio_finding_market_capability_uses TO chio_market_runtime_test;
        GRANT SELECT, INSERT, UPDATE, DELETE ON chio_finding_market_security_events TO chio_market_runtime_test;
        "#,
    )
    .execute(&admin_pool)
    .await?;
    let runtime_pool = sqlx::PgPool::connect(&runtime_url).await?;
    let store =
        PostgresFindingMarketStore::from_pool_for_integration_tests(runtime_pool.clone(), 8);

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let tenant_a = HostedTenantId::new(format!("integration-a-{nonce}"))?;
    let tenant_b = HostedTenantId::new(format!("integration-b-{nonce}"))?;
    store.register_tenant(&tenant_a, 1_700_000_000).await?;
    store.register_tenant(&tenant_b, 1_700_000_000).await?;

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

    let first_lease = store
        .claim_due_jobs(&tenant_a, "worker-a", 1_700_000_010, 10, 1)
        .await?;
    assert_eq!(first_lease.len(), 1);
    assert_eq!(first_lease[0].state, HostedJobState::Leased);
    assert!(store
        .claim_due_jobs(&tenant_a, "worker-b", 1_700_000_015, 10, 1)
        .await?
        .is_empty());
    let recovered = store
        .claim_due_jobs(&tenant_a, "worker-a", 1_700_000_021, 10, 1)
        .await?;
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
        .complete_job(&tenant_a, "job-1", &stale_lease, result, 1_700_000_022,)
        .await
        .is_err());
    assert_eq!(
        store
            .complete_job(&tenant_a, "job-1", &recovered_lease, result, 1_700_000_022,)
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
    store
        .put_job(
            &tenant_a,
            "job-exhausted",
            "finding.verify",
            &"b".repeat(64),
            br#"{"findingId":"terminal"}"#,
            1_700_000_023,
            1_700_000_023,
        )
        .await?;
    let exhausted_lease = store
        .claim_due_jobs(&tenant_a, "worker-c", 1_700_000_024, 10, 1)
        .await?;
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
            1_700_000_025,
        )
        .await?;
    let exhausted = store
        .get_job(&tenant_a, "job-exhausted")
        .await?
        .ok_or("exhausted job missing")?;
    assert_eq!(exhausted.state, HostedJobState::Exhausted);
    assert!(store
        .claim_due_jobs(&tenant_a, "worker-d", 1_700_000_100, 10, 1)
        .await?
        .is_empty());
    store.set_tenant_enabled(&tenant_a, false).await?;
    assert!(matches!(
        store.get_job(&tenant_a, "job-1").await,
        Err(HostedMarketStoreError::TenantDisabled)
    ));
    Ok(())
}
