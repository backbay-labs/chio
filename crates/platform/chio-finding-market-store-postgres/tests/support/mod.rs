//! Shared harness for the hosted market integration suite.
//!
//! The suite is one sequenced test rather than many, and splitting it
//! needs one thing first.
//!
//! Some scenarios assert on schema state rather than on rows: the
//! runtime-boundary checks weaken an RLS policy, prove the boundary
//! refuses it, and restore it. Those mutations are database-wide, so a
//! second test running concurrently against the same schema can observe
//! the weakened window and fail for a reason unrelated to what it
//! asserts.
//!
//! The prerequisite is a schema per test: each test creating its own
//! uniquely named schema with every pool setting `search_path` to it, so
//! a global mutation is global only to the test that made it. Tenant
//! scoping is not enough on its own, because the mutations these
//! assertions rely on are not tenant scoped.

use super::*;
use std::time::Duration;

use chio_core_types::capability::scope::MonetaryAmount;
use chio_finding::{
    compute_status_epoch_id, FindingHostedPurchaseVerdict, FindingHostedSettlementTerminal,
    FindingPurchaseResult, FindingStatusEpoch, FindingVoluntaryRetraction,
    FindingVoluntaryRetractionReason, FINDING_PURCHASE_RESULT_SCHEMA_V1,
    FINDING_STATUS_EPOCH_SCHEMA_V1, FINDING_STATUS_SIGNATURE_DOMAIN,
    FINDING_VOLUNTARY_RETRACTION_SCHEMA_V1,
};

#[allow(clippy::too_many_arguments)]
pub(super) async fn assert_catalog_retractions(
    store: &PostgresFindingMarketStore,
    tenant: &HostedTenantId,
    other_tenant: &HostedTenantId,
    signer: &Keypair,
    finding_id: &str,
    replicator: &PostgresFindingMarketReplicator,
    source_signer: &Keypair,
    authority_now: u64,
) -> Result<(), Box<dyn Error>> {
    let foreign_signer = Keypair::from_seed(&[93_u8; 32]);
    let cross_seller_retraction = SignedExportEnvelope::sign(
        FindingVoluntaryRetraction {
            schema: FINDING_VOLUNTARY_RETRACTION_SCHEMA_V1.to_owned(),
            intent_id: "b".repeat(64),
            finding_id: finding_id.to_owned(),
            seller: foreign_signer.public_key(),
            status_feed_ref: "integration-status".to_owned(),
            reason: FindingVoluntaryRetractionReason::SellerVoluntaryRetraction,
            issued_at: authority_now,
            inclusion_deadline: authority_now + 300,
        },
        &foreign_signer,
    )?;
    assert!(matches!(
        store
            .record_voluntary_retraction(
                tenant,
                &cross_seller_retraction,
                &HostedDomainWrite::new("cross-seller-retraction", 0, None, authority_now)?,
            )
            .await,
        Err(HostedMarketStoreError::Invalid("subject finding binding"))
    ));
    let wrong_feed_retraction = SignedExportEnvelope::sign(
        FindingVoluntaryRetraction {
            schema: FINDING_VOLUNTARY_RETRACTION_SCHEMA_V1.to_owned(),
            intent_id: "a".repeat(64),
            finding_id: finding_id.to_owned(),
            seller: signer.public_key(),
            status_feed_ref: "wrong-status-feed".to_owned(),
            reason: FindingVoluntaryRetractionReason::SellerVoluntaryRetraction,
            issued_at: authority_now,
            inclusion_deadline: authority_now + 300,
        },
        signer,
    )?;
    assert!(matches!(
        store
            .record_voluntary_retraction(
                tenant,
                &wrong_feed_retraction,
                &HostedDomainWrite::new("wrong-feed-retraction", 0, None, authority_now)?,
            )
            .await,
        Err(HostedMarketStoreError::Invalid("subject finding binding"))
    ));
    let retraction = SignedExportEnvelope::sign(
        FindingVoluntaryRetraction {
            schema: FINDING_VOLUNTARY_RETRACTION_SCHEMA_V1.to_owned(),
            intent_id: "c".repeat(64),
            finding_id: finding_id.to_owned(),
            seller: signer.public_key(),
            status_feed_ref: "integration-status".to_owned(),
            reason: FindingVoluntaryRetractionReason::SellerVoluntaryRetraction,
            issued_at: authority_now,
            inclusion_deadline: authority_now + 300,
        },
        signer,
    )?;
    assert_eq!(
        store
            .record_voluntary_retraction(
                tenant,
                &retraction,
                &HostedDomainWrite::new("retraction-market-finding", 0, None, authority_now)?,
            )
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    let query = vec![finding_id.to_owned(), "d".repeat(64)];
    assert_eq!(
        store.catalog_non_live_finding_ids(tenant, &query).await?,
        [finding_id.to_owned()].into_iter().collect()
    );
    assert!(store
        .catalog_non_live_finding_ids(other_tenant, &query)
        .await?
        .is_empty());
    assert!(matches!(
        store
            .catalog_non_live_finding_ids(tenant, &[finding_id.to_owned(), finding_id.to_owned()])
            .await,
        Err(HostedMarketStoreError::Invalid("status query"))
    ));
    let retraction_projection_sha256 = replicator.target_projection_sha256(tenant).await?;
    let retraction_sequence = store.authority_state(tenant).await?.last_outbox_sequence;
    append_replication_check(
        replicator,
        tenant,
        source_signer,
        ReplicationCheckSpec {
            authority_epoch: 3,
            through_sequence: retraction_sequence,
            projection_sha256: &retraction_projection_sha256,
            source_authority: HostedMarketAuthority::Postgres,
            checked_at: authority_now,
        },
    )
    .await?;
    let mut epoch = FindingStatusEpoch {
        schema: FINDING_STATUS_EPOCH_SCHEMA_V1.to_owned(),
        status_epoch_id: String::new(),
        signature_domain: FINDING_STATUS_SIGNATURE_DOMAIN.to_owned(),
        status_map_version: "sparse_map_v1".to_owned(),
        proof_semantics: "siblings_leaf_to_root_v1".to_owned(),
        feed_id: "integration-status".to_owned(),
        key_domain_nonce: 3_318_287_169_837_494,
        map_epoch: 1,
        operator_id: "integration-status-operator".to_owned(),
        operator_key: signer.public_key(),
        operator_key_epoch: 1,
        root_hash: "e".repeat(64),
        tree_depth: 256,
        hash_algorithm: "sha256".to_owned(),
        key_hash_domain: "chio.finding.status.v1:key".to_owned(),
        empty_leaf_domain: "chio.finding.status.v1:empty-leaf".to_owned(),
        occupied_leaf_domain: "chio.finding.status.v1:occupied-leaf".to_owned(),
        branch_domain: "chio.finding.status.v1:branch".to_owned(),
        empty_leaf_hash: sha256_hex(b"chio.finding.status.v1:empty-leaf\0"),
        anchor_refs: Vec::new(),
        generated_at: authority_now,
        valid_from: authority_now,
        valid_until: authority_now + 300,
    };
    epoch.status_epoch_id = compute_status_epoch_id(&epoch)?;
    let signed_epoch = SignedExportEnvelope::sign(epoch, signer)?;
    store
        .publish_status_epoch(
            tenant,
            &signed_epoch,
            &HostedDomainWrite::new("catalog-status-epoch", 0, None, authority_now)?,
        )
        .await?;
    assert_eq!(
        store.catalog_non_live_finding_ids(tenant, &query).await?,
        query.iter().cloned().collect()
    );
    let projection_sha256 = replicator.target_projection_sha256(tenant).await?;
    let through_sequence = store.authority_state(tenant).await?.last_outbox_sequence;
    append_replication_check(
        replicator,
        tenant,
        source_signer,
        ReplicationCheckSpec {
            authority_epoch: 3,
            through_sequence,
            projection_sha256: &projection_sha256,
            source_authority: HostedMarketAuthority::Postgres,
            checked_at: authority_now,
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn assert_terminal_job_retention_gc(
    retention: &PostgresFindingMarketRetention,
    admin_pool: &sqlx::PgPool,
    store: &PostgresFindingMarketStore,
    tenant: &HostedTenantId,
    retention_signer: &Keypair,
    retention_public_key: &chio_core_types::crypto::PublicKey,
    authority_now: u64,
    request_sha256: &str,
    payload: &[u8],
) -> Result<(), Box<dyn Error>> {
    let terminal_commitment = retention.journal_commitment(tenant).await?;
    let terminal_checkpoint_body = HostedJournalCheckpointBody {
        schema: HOSTED_JOURNAL_CHECKPOINT_SCHEMA.to_owned(),
        tenant_id: tenant.as_str().to_owned(),
        aggregate_heads_sha256: terminal_commitment.aggregate_heads_sha256,
        terminal_jobs_sha256: terminal_commitment.terminal_jobs_sha256,
        previous_checkpoint_sha256: terminal_commitment.previous_checkpoint_sha256,
        migration_version: terminal_commitment.migration_version,
        configuration_revision: "integration-revision-1".to_owned(),
        created_at: authority_now + 20,
    };
    let terminal_checkpoint_a =
        SignedExportEnvelope::sign(terminal_checkpoint_body.clone(), retention_signer)?;
    let terminal_checkpoint_b = SignedExportEnvelope::sign(
        HostedJournalCheckpointBody {
            created_at: authority_now + 21,
            ..terminal_checkpoint_body
        },
        retention_signer,
    )?;
    let (checkpoint_a_result, checkpoint_b_result) = tokio::join!(
        retention.append_journal_checkpoint(tenant, retention_public_key, &terminal_checkpoint_a,),
        retention.append_journal_checkpoint(tenant, retention_public_key, &terminal_checkpoint_b,),
    );
    let checkpoint_a_inserted = matches!(&checkpoint_a_result, Ok(HostedJobWriteOutcome::Inserted));
    let checkpoint_b_inserted = matches!(&checkpoint_b_result, Ok(HostedJobWriteOutcome::Inserted));
    assert!(
        (checkpoint_a_inserted
            && matches!(&checkpoint_b_result, Err(HostedMarketStoreError::Conflict)))
            || (checkpoint_b_inserted
                && matches!(&checkpoint_a_result, Err(HostedMarketStoreError::Conflict)))
    );
    let terminal_checkpoint = if checkpoint_a_inserted {
        &terminal_checkpoint_a
    } else {
        &terminal_checkpoint_b
    };
    let terminal_checkpoint_sha256 = sha256_hex(&canonical_json_bytes(terminal_checkpoint)?);
    let terminal_job_sha256: String = sqlx::query_scalar(
        r#"SELECT member_sha256
           FROM chio_finding_market_journal_checkpoint_members
           WHERE tenant_id = $1 AND checkpoint_sha256 = $2
             AND member_kind = 'job' AND member_family = $3
             AND member_id = $4 AND member_revision = 0"#,
    )
    .bind(tenant.as_str())
    .bind(&terminal_checkpoint_sha256)
    .bind("finding.purchase")
    .bind("job-1")
    .fetch_one(admin_pool)
    .await?;
    let terminal_job_target = HostedRetentionTarget {
        resource_kind: HostedRetentionResourceKind::Job,
        resource_family: "finding.purchase".to_owned(),
        resource_id: "job-1".to_owned(),
        resource_revision: 0,
        resource_sha256: terminal_job_sha256,
    };
    let terminal_job_manifest = SignedExportEnvelope::sign(
        HostedArchiveManifestBody {
            schema: HOSTED_ARCHIVE_MANIFEST_SCHEMA.to_owned(),
            tenant_id: tenant.as_str().to_owned(),
            target: terminal_job_target.clone(),
            covered_checkpoint_sha256: terminal_checkpoint_sha256,
            object_uri: "s3://chio-test/job-1.json".to_owned(),
            object_sha256: "d".repeat(64),
            object_size: 128,
            configuration_revision: "integration-revision-1".to_owned(),
            previous_archive_sha256: None,
            created_at: authority_now + 22,
        },
        retention_signer,
    )?;
    retention
        .append_archive_manifest(tenant, retention_public_key, &terminal_job_manifest)
        .await?;
    let terminal_job_archive_sha256 = sha256_hex(&canonical_json_bytes(&terminal_job_manifest)?);
    let terminal_job_restore = SignedExportEnvelope::sign(
        HostedRestoreVerificationBody {
            schema: HOSTED_RESTORE_VERIFICATION_SCHEMA.to_owned(),
            tenant_id: tenant.as_str().to_owned(),
            archive_sha256: terminal_job_archive_sha256.clone(),
            restored_resource_sha256: terminal_job_target.resource_sha256.clone(),
            verified_at: authority_now + 23,
        },
        retention_signer,
    )?;
    retention
        .append_restore_verification(tenant, retention_public_key, &terminal_job_restore)
        .await?;
    let terminal_job_gc = SignedExportEnvelope::sign(
        HostedGcReceiptBody {
            schema: HOSTED_GC_RECEIPT_SCHEMA.to_owned(),
            tenant_id: tenant.as_str().to_owned(),
            archive_sha256: terminal_job_archive_sha256,
            target: terminal_job_target,
            completed_at: authority_now + 24,
        },
        retention_signer,
    )?;
    assert_eq!(
        retention
            .garbage_collect(tenant, retention_public_key, &terminal_job_gc)
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    assert!(store.get_job(tenant, "job-1").await?.is_none());
    assert!(matches!(
        store
            .put_job(
                tenant,
                "job-1",
                "finding.purchase",
                request_sha256,
                payload,
                authority_now + 25,
                authority_now + 25,
            )
            .await,
        Err(HostedMarketStoreError::Conflict)
    ));
    Ok(())
}

pub(super) async fn assert_worker_job_boundary(
    worker_pool: &sqlx::PgPool,
    tenant: &HostedTenantId,
) -> Result<(), Box<dyn Error>> {
    let mut transaction = worker_pool.begin().await?;
    sqlx::query("SELECT set_config('chio.tenant_id', $1, TRUE)")
        .bind(tenant.as_str())
        .execute(&mut *transaction)
        .await?;
    let direct_mutation =
        sqlx::query("UPDATE chio_finding_market_jobs SET state = 'completed' WHERE tenant_id = $1")
            .bind(tenant.as_str())
            .execute(&mut *transaction)
            .await;
    assert!(direct_mutation.is_err());
    transaction.rollback().await?;
    Ok(())
}

pub(super) async fn assert_disabled_tenant_blocks_worker_transitions(
    store: &PostgresFindingMarketStore,
    worker_pool: &sqlx::PgPool,
    nonce: u128,
) -> Result<(), Box<dyn Error>> {
    let tenant = HostedTenantId::new(format!("integration-disabled-worker-{nonce}"))?;
    store
        .register_tenant(
            &tenant,
            &HostedTenantLimits::new(1, 1, 1_000, "disabled-worker-revision-1")?,
            1_700_000_000,
        )
        .await?;
    store
        .put_job(
            &tenant,
            "disabled-worker-job",
            "finding.verify",
            &"a".repeat(64),
            br#"{"findingId":"disabled-worker"}"#,
            1_700_000_000,
            1_700_000_000,
        )
        .await?;
    let claimed = store
        .claim_due_jobs(&tenant, "disabled-worker", 60, 1)
        .await?;
    assert_eq!(claimed.len(), 1);
    let lease_fence = i64::try_from(claimed[0].lease_fence)?;
    store.set_tenant_enabled(&tenant, false).await?;

    let mut transaction = worker_pool.begin().await?;
    sqlx::query("SELECT set_config('chio.tenant_id', $1, TRUE)")
        .bind(tenant.as_str())
        .execute(&mut *transaction)
        .await?;
    let claimed_after_disable: Vec<(String,)> =
        sqlx::query_as("SELECT job_id FROM chio_finding_market_claim_jobs($1, $2, $3, $4)")
            .bind(tenant.as_str())
            .bind("disabled-worker")
            .bind(60_i64)
            .bind(1_i64)
            .fetch_all(&mut *transaction)
            .await?;
    assert!(claimed_after_disable.is_empty());
    let renewed: Option<i64> =
        sqlx::query_scalar("SELECT chio_finding_market_renew_job_lease($1, $2, $3, $4, $5)")
            .bind(tenant.as_str())
            .bind("disabled-worker-job")
            .bind("disabled-worker")
            .bind(lease_fence)
            .bind(60_i64)
            .fetch_one(&mut *transaction)
            .await?;
    assert!(renewed.is_none());
    let result = br#"{"status":"disabled"}"#;
    let completed: i16 =
        sqlx::query_scalar("SELECT chio_finding_market_complete_job($1, $2, $3, $4, $5, $6)")
            .bind(tenant.as_str())
            .bind("disabled-worker-job")
            .bind("disabled-worker")
            .bind(lease_fence)
            .bind(sha256_hex(result))
            .bind(result.as_slice())
            .fetch_one(&mut *transaction)
            .await?;
    assert_eq!(completed, 4);
    let failed: bool =
        sqlx::query_scalar("SELECT chio_finding_market_fail_job($1, $2, $3, $4, $5, $6)")
            .bind(tenant.as_str())
            .bind("disabled-worker-job")
            .bind("disabled-worker")
            .bind(lease_fence)
            .bind("disabled")
            .bind(1_i64)
            .fetch_one(&mut *transaction)
            .await?;
    assert!(!failed);
    let relinquished: bool =
        sqlx::query_scalar("SELECT chio_finding_market_relinquish_job_lease($1, $2, $3, $4)")
            .bind(tenant.as_str())
            .bind("disabled-worker-job")
            .bind("disabled-worker")
            .bind(lease_fence)
            .fetch_one(&mut *transaction)
            .await?;
    assert!(!relinquished);
    let exhausted: bool =
        sqlx::query_scalar("SELECT chio_finding_market_exhaust_job($1, $2, $3, $4, $5)")
            .bind(tenant.as_str())
            .bind("disabled-worker-job")
            .bind("disabled-worker")
            .bind(lease_fence)
            .bind("disabled")
            .fetch_one(&mut *transaction)
            .await?;
    assert!(!exhausted);
    let retained: (String, Option<String>, i64, i64) = sqlx::query_as(
        "SELECT state, lease_owner, lease_fence, attempt_count FROM chio_finding_market_jobs WHERE tenant_id = $1 AND job_id = $2",
    )
    .bind(tenant.as_str())
    .bind("disabled-worker-job")
    .fetch_one(&mut *transaction)
    .await?;
    assert_eq!(
        retained,
        (
            "leased".to_owned(),
            Some("disabled-worker".to_owned()),
            lease_fence,
            1
        )
    );
    transaction.rollback().await?;
    Ok(())
}

pub(super) async fn assert_tenant_disablement_serializes(
    store: &PostgresFindingMarketStore,
    runtime_pool: &sqlx::PgPool,
    tenant: &HostedTenantId,
) -> Result<(), Box<dyn Error>> {
    let scoped_write = store
        .begin_tenant_write_for_integration_tests(tenant)
        .await?;
    let disable_store =
        PostgresFindingMarketStore::from_pool_for_integration_tests(runtime_pool.clone(), 8);
    let disable_tenant = tenant.clone();
    let mut disable = tokio::spawn(async move {
        disable_store
            .set_tenant_enabled(&disable_tenant, false)
            .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut disable)
            .await
            .is_err()
    );
    scoped_write.commit().await?;
    tokio::time::timeout(Duration::from_secs(5), disable).await???;
    assert!(matches!(
        store.probe_tenant(tenant).await,
        Err(HostedMarketStoreError::TenantDisabled)
    ));
    store.set_tenant_enabled(tenant, true).await?;
    Ok(())
}

pub(super) async fn assert_forged_job_digest_rejected(
    worker_pool: &sqlx::PgPool,
    tenant: &HostedTenantId,
    job_id: &str,
    lease: &chio_finding_market_store_postgres::HostedJobLease,
    result: &[u8],
) -> Result<(), Box<dyn Error>> {
    let mut transaction = worker_pool.begin().await?;
    sqlx::query("SELECT set_config('chio.tenant_id', $1, TRUE)")
        .bind(tenant.as_str())
        .execute(&mut *transaction)
        .await?;
    let outcome: i16 =
        sqlx::query_scalar("SELECT chio_finding_market_complete_job($1, $2, $3, $4, $5, $6)")
            .bind(tenant.as_str())
            .bind(job_id)
            .bind(lease.worker_id())
            .bind(i64::try_from(lease.fence())?)
            .bind("f".repeat(64))
            .bind(result)
            .fetch_one(&mut *transaction)
            .await?;
    assert_eq!(outcome, 4);
    transaction.rollback().await?;
    Ok(())
}

pub(super) async fn assert_multi_replica_leases_and_shutdown_refunds(
    store: &PostgresFindingMarketStore,
    admin_pool: &sqlx::PgPool,
    tenant: &HostedTenantId,
) -> Result<(), Box<dyn Error>> {
    for index in 1..=3 {
        store
            .put_job(
                tenant,
                &format!("concurrency-job-{index}"),
                "finding.verify",
                &format!("{index:x}").repeat(64),
                format!(r#"{{"findingId":"concurrency-{index}"}}"#).as_bytes(),
                1_700_000_000,
                1_700_000_000,
            )
            .await?;
    }
    let replica_a = store.claim_due_jobs(tenant, "replica-a", 10, 1).await?;
    assert_eq!(replica_a.len(), 1);
    let replica_b = store.claim_due_jobs(tenant, "replica-b", 10, 2).await?;
    assert_eq!(
        replica_b.len(),
        2,
        "a replica batch must consume all tenant-global slots still available"
    );
    assert!(store
        .claim_due_jobs(tenant, "replica-c", 10, 2)
        .await?
        .is_empty());

    let relinquished_job = &replica_b[0];
    let relinquished_lease = chio_finding_market_store_postgres::HostedJobLease::new(
        "replica-b",
        relinquished_job.lease_fence,
    )?;
    sqlx::query(
        "UPDATE chio_finding_market_jobs SET lease_expires_at = floor(extract(epoch from clock_timestamp()))::bigint - 1 WHERE tenant_id = $1 AND job_id = $2",
    )
    .bind(tenant.as_str())
    .bind(&relinquished_job.job_id)
    .execute(admin_pool)
    .await?;
    store
        .relinquish_job_lease(tenant, &relinquished_job.job_id, &relinquished_lease)
        .await?;
    let relinquished = store
        .get_job(tenant, &relinquished_job.job_id)
        .await?
        .ok_or("relinquished job missing")?;
    assert_eq!(relinquished.state, HostedJobState::Pending);
    assert_eq!(relinquished.attempt_count, 0);
    assert!(matches!(
        store
            .relinquish_job_lease(tenant, &relinquished_job.job_id, &relinquished_lease)
            .await,
        Err(HostedMarketStoreError::LeaseLost)
    ));

    let reclaimed = store.claim_due_jobs(tenant, "replica-c", 10, 2).await?;
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(reclaimed[0].job_id, relinquished_job.job_id);
    assert_eq!(reclaimed[0].attempt_count, 1);
    assert!(reclaimed[0].lease_fence > relinquished_job.lease_fence);
    let reclaimed_lease = chio_finding_market_store_postgres::HostedJobLease::new(
        "replica-c",
        reclaimed[0].lease_fence,
    )?;
    store
        .fail_job(
            tenant,
            &reclaimed[0].job_id,
            &reclaimed_lease,
            "transient_failure",
            1,
        )
        .await?;
    sqlx::query(
        "UPDATE chio_finding_market_jobs SET available_at = 1 WHERE tenant_id = $1 AND job_id = $2",
    )
    .bind(tenant.as_str())
    .bind(&reclaimed[0].job_id)
    .execute(admin_pool)
    .await?;

    let claimed_after_failure = store.claim_due_jobs(tenant, "replica-d", 10, 1).await?;
    assert_eq!(claimed_after_failure.len(), 1);
    assert_eq!(claimed_after_failure[0].attempt_count, 2);
    let claimed_after_failure_lease = chio_finding_market_store_postgres::HostedJobLease::new(
        "replica-d",
        claimed_after_failure[0].lease_fence,
    )?;
    store
        .relinquish_job_lease(
            tenant,
            &claimed_after_failure[0].job_id,
            &claimed_after_failure_lease,
        )
        .await?;
    let relinquished_after_failure = store
        .get_job(tenant, &claimed_after_failure[0].job_id)
        .await?
        .ok_or("relinquished retry job missing")?;
    assert_eq!(relinquished_after_failure.state, HostedJobState::Pending);
    assert_eq!(relinquished_after_failure.attempt_count, 1);
    assert!(relinquished_after_failure.lease_fence > relinquished_job.lease_fence);
    Ok(())
}

pub(super) fn signed_domain_payload(
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

pub(super) fn signed_principal_replication_event(
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

pub(super) async fn append_replication_check(
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

pub(super) struct ReplicationCheckSpec<'a> {
    pub(super) authority_epoch: u64,
    pub(super) through_sequence: u64,
    pub(super) projection_sha256: &'a str,
    pub(super) source_authority: HostedMarketAuthority,
    pub(super) checked_at: u64,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn apply_authority_transition(
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

pub(super) async fn install_legacy_migration_fixture(
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn Error>> {
    const LEGACY: &[(i64, &str, &str)] = &[
        (
            1,
            "hosted_market",
            include_str!("../../migrations/0001_hosted_market.sql"),
        ),
        (
            2,
            "terminal_jobs",
            include_str!("../../migrations/0002_terminal_jobs.sql"),
        ),
        (
            3,
            "lease_fencing",
            include_str!("../../migrations/0003_lease_fencing.sql"),
        ),
        (
            4,
            "hosted_auth",
            include_str!("../../migrations/0004_hosted_auth.sql"),
        ),
        (
            5,
            "market_aggregates",
            include_str!("../../migrations/0005_market_aggregates.sql"),
        ),
        (
            6,
            "tenant_registry_rls",
            include_str!("../../migrations/0006_tenant_registry_rls.sql"),
        ),
        (
            7,
            "tenant_limits",
            include_str!("../../migrations/0007_tenant_limits.sql"),
        ),
        (
            8,
            "append_only_aggregates",
            include_str!("../../migrations/0008_append_only_aggregates.sql"),
        ),
        (
            9,
            "aggregate_checkpoints",
            include_str!("../../migrations/0009_aggregate_checkpoints.sql"),
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

pub(super) async fn migrate_legacy_fixture(
    admin_pool: &sqlx::PgPool,
    migrator_url: &str,
) -> Result<(), Box<dyn Error>> {
    let migrator_pool = sqlx::postgres::PgPoolOptions::new()
        .min_connections(1)
        .max_connections(1)
        .connect(migrator_url)
        .await?;
    install_legacy_migration_fixture(&migrator_pool).await?;
    sqlx::query(
        r#"INSERT INTO chio_finding_market_tenants (
               tenant_id, enabled, created_at, max_concurrent_jobs,
               max_queued_jobs, max_monthly_spend_units, configuration_revision
           ) VALUES ($1, TRUE, 1700000000, 1, 10, 1000, 'legacy-probe')"#,
    )
    .bind("legacy-principal-probe")
    .execute(admin_pool)
    .await?;
    sqlx::query(
        r#"INSERT INTO chio_finding_market_principals (
               tenant_id, principal_id, role, capability_public_key_hex,
               enabled, created_at, updated_at
           ) VALUES ($1, 'legacy-buyer', 'buyer', $2, TRUE, 1700000000, 1700000000)"#,
    )
    .bind("legacy-principal-probe")
    .bind("9".repeat(64))
    .execute(admin_pool)
    .await?;
    let migrator = PostgresFindingMarketMigrator::from_pool_for_integration_tests(migrator_pool);
    assert!(migrator.migrate().await.is_err());
    let migration_eleven_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE version = 11")
            .fetch_one(admin_pool)
            .await?;
    assert_eq!(migration_eleven_count, 0);
    let retained_legacy_principal_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chio_finding_market_principals WHERE tenant_id = $1",
    )
    .bind("legacy-principal-probe")
    .fetch_one(admin_pool)
    .await?;
    assert_eq!(retained_legacy_principal_count, 1);
    sqlx::query("DELETE FROM chio_finding_market_principals WHERE tenant_id = $1")
        .bind("legacy-principal-probe")
        .execute(admin_pool)
        .await?;
    sqlx::query("DELETE FROM chio_finding_market_tenants WHERE tenant_id = $1")
        .bind("legacy-principal-probe")
        .execute(admin_pool)
        .await?;
    migrator.migrate().await?;
    migrator.migrate().await?;
    let migration_checksum: Vec<u8> =
        sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version = 1")
            .fetch_one(admin_pool)
            .await?;
    sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = 1")
        .bind(vec![0_u8; migration_checksum.len()])
        .execute(admin_pool)
        .await?;
    assert!(matches!(
        migrator.migrate().await,
        Err(HostedMarketStoreError::MigrationDrift)
    ));
    sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = 1")
        .bind(migration_checksum)
        .execute(admin_pool)
        .await?;
    migrator.migrate().await?;
    Ok(())
}

pub(super) async fn assert_legacy_delivery_upgrade_rejects(
    admin_pool: &sqlx::PgPool,
    tenant: &HostedTenantId,
) -> Result<(), Box<dyn Error>> {
    let mut transaction = admin_pool.begin().await?;
    sqlx::raw_sql(
        r#"
        ALTER TABLE chio_finding_market_domain_event_contracts
            DISABLE TRIGGER chio_finding_market_domain_event_contracts_immutable;
        DELETE FROM chio_finding_market_domain_event_contracts
        WHERE aggregate_kind = 'delivery'
          AND event_kind = 'delivery.accepted'
          AND artifact_schema = 'chio.finding.hosted-authenticated-delivery.v1';
        INSERT INTO chio_finding_market_domain_event_contracts (
            aggregate_kind, event_kind, artifact_schema, signed_artifact
        ) VALUES (
            'delivery', 'delivery.accepted', 'chio.finding.delivery.v1', FALSE
        );
        ALTER TABLE chio_finding_market_domain_event_contracts
            ENABLE TRIGGER chio_finding_market_domain_event_contracts_immutable;
        "#,
    )
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r#"INSERT INTO chio_finding_market_replication_outbox (
               tenant_id, authority_epoch, sequence, aggregate_kind,
               aggregate_id, expected_revision, expected_event_sha256,
               event_id, event_kind, artifact_schema, payload_sha256,
               payload_json, event_sha256, committed_at
           ) VALUES (
               $1, 1, 999, 'delivery', 'legacy-delivery', 0, NULL,
               'legacy-delivery-event', 'delivery.accepted',
               'chio.finding.delivery.v1', $2, $3, $4, 1700000000
           )"#,
    )
    .bind(tenant.as_str())
    .bind("a".repeat(64))
    .bind(b"{}".as_slice())
    .bind("b".repeat(64))
    .execute(&mut *transaction)
    .await?;
    let unsafe_upgrade = sqlx::raw_sql(include_str!(
        "../../migrations/0016_authenticated_delivery_receipt.sql"
    ))
    .execute(&mut *transaction)
    .await;
    assert!(unsafe_upgrade.is_err());
    transaction.rollback().await?;
    Ok(())
}

pub(super) async fn assert_atomic_purchase_recovery(
    store: &PostgresFindingMarketStore,
    tenant: &HostedTenantId,
    domain_signer: &Keypair,
    market_finding_id: &str,
    replicator: &PostgresFindingMarketReplicator,
    source_signer: &Keypair,
    authority_now: u64,
) -> Result<(), Box<dyn Error>> {
    let projection_sha256 = replicator.target_projection_sha256(tenant).await?;
    append_replication_check(
        replicator,
        tenant,
        source_signer,
        ReplicationCheckSpec {
            authority_epoch: 3,
            through_sequence: 2,
            projection_sha256: &projection_sha256,
            source_authority: HostedMarketAuthority::Postgres,
            checked_at: authority_now,
        },
    )
    .await?;
    let purchase_result = SignedExportEnvelope::sign(
        FindingPurchaseResult {
            schema: FINDING_PURCHASE_RESULT_SCHEMA_V1.to_owned(),
            result_id: "a".repeat(64),
            request_id: "a".repeat(64),
            finding_id: market_finding_id.to_owned(),
            payer: domain_signer.public_key(),
            reservation_id: "purchase-spend-after-release".to_owned(),
            purchase_intent_id: "recovery-intent-a".to_owned(),
            authoritative_payment_operation_id: "recovery-payment-a".to_owned(),
            verdict: FindingHostedPurchaseVerdict::Allow,
            settlement: FindingHostedSettlementTerminal::Captured,
            accepted_price: MonetaryAmount {
                units: 4_000,
                currency: "USD".to_owned(),
            },
            realized_spend: MonetaryAmount {
                units: 4_000,
                currency: "USD".to_owned(),
            },
            delivery_receipt_sha256: "4".repeat(64),
            purchase_record_sha256: Some("5".repeat(64)),
            failed_delivery_sha256: None,
            output_sha256: Some("6".repeat(64)),
            recorded_at: authority_now,
        },
        domain_signer,
    )?;
    let reveal_write = HostedDomainWrite::new("recovery-reveal-a", 0, None, authority_now)?;
    let terminal_write = HostedDomainWrite::new("recovery-terminal-a", 0, None, authority_now)?;
    let recovery = store
        .recover_purchase_result(tenant, &purchase_result, &reveal_write, &terminal_write)
        .await?;
    assert_eq!(recovery.reveal, HostedJobWriteOutcome::Inserted);
    assert_eq!(recovery.terminal, HostedJobWriteOutcome::Inserted);
    assert_eq!(recovery.spend, HostedJobWriteOutcome::Inserted);
    assert_eq!(store.authority_state(tenant).await?.last_outbox_sequence, 4);
    let recovery_retry = store
        .recover_purchase_result(tenant, &purchase_result, &reveal_write, &terminal_write)
        .await?;
    assert_eq!(recovery_retry.reveal, HostedJobWriteOutcome::ExactReplay);
    assert_eq!(recovery_retry.terminal, HostedJobWriteOutcome::ExactReplay);
    assert_eq!(recovery_retry.spend, HostedJobWriteOutcome::ExactReplay);
    let recovered_spend = store
        .monthly_spend_reservation(tenant, "purchase-spend-after-release")
        .await?
        .ok_or("recovered spend reservation missing")?;
    assert_eq!(
        recovered_spend.state,
        chio_finding_market_store_postgres::HostedSpendState::Committed
    );
    let projection_sha256 = replicator.target_projection_sha256(tenant).await?;
    append_replication_check(
        replicator,
        tenant,
        source_signer,
        ReplicationCheckSpec {
            authority_epoch: 3,
            through_sequence: 4,
            projection_sha256: &projection_sha256,
            source_authority: HostedMarketAuthority::Postgres,
            checked_at: authority_now,
        },
    )
    .await?;

    let conflict_base = SignedExportEnvelope::sign(
        FindingPurchaseResult {
            schema: FINDING_PURCHASE_RESULT_SCHEMA_V1.to_owned(),
            result_id: "b".repeat(64),
            request_id: "b".repeat(64),
            finding_id: market_finding_id.to_owned(),
            payer: domain_signer.public_key(),
            reservation_id: "purchase-spend-release".to_owned(),
            purchase_intent_id: "recovery-intent-conflict".to_owned(),
            authoritative_payment_operation_id: "recovery-payment-conflict".to_owned(),
            verdict: FindingHostedPurchaseVerdict::Deny,
            settlement: FindingHostedSettlementTerminal::Released,
            accepted_price: MonetaryAmount {
                units: 4_000,
                currency: "USD".to_owned(),
            },
            realized_spend: MonetaryAmount {
                units: 0,
                currency: "USD".to_owned(),
            },
            delivery_receipt_sha256: "7".repeat(64),
            purchase_record_sha256: None,
            failed_delivery_sha256: Some("8".repeat(64)),
            output_sha256: None,
            recorded_at: authority_now,
        },
        domain_signer,
    )?;
    let conflict_reveal_write =
        HostedDomainWrite::new("recovery-reveal-conflict", 0, None, authority_now)?;
    store
        .commit_reveal(tenant, &conflict_base, &conflict_reveal_write)
        .await?;
    let projection_sha256 = replicator.target_projection_sha256(tenant).await?;
    append_replication_check(
        replicator,
        tenant,
        source_signer,
        ReplicationCheckSpec {
            authority_epoch: 3,
            through_sequence: 5,
            projection_sha256: &projection_sha256,
            source_authority: HostedMarketAuthority::Postgres,
            checked_at: authority_now,
        },
    )
    .await?;
    let mut conflicting_body = conflict_base.body.clone();
    conflicting_body.delivery_receipt_sha256 = "9".repeat(64);
    let conflicting_result = SignedExportEnvelope::sign(conflicting_body, domain_signer)?;
    let conflict_terminal_write =
        HostedDomainWrite::new("recovery-terminal-conflict", 0, None, authority_now)?;
    assert!(matches!(
        store
            .recover_purchase_result(
                tenant,
                &conflicting_result,
                &conflict_reveal_write,
                &conflict_terminal_write,
            )
            .await,
        Err(HostedMarketStoreError::Conflict)
    ));
    assert!(store
        .domain_projection(
            tenant,
            HostedMarketDomainEventKind::PurchaseSettled,
            &conflicting_result.body.result_id,
        )
        .await?
        .is_none());
    assert_eq!(store.authority_state(tenant).await?.last_outbox_sequence, 5);
    assert_eq!(
        store
            .monthly_spend_reservation(tenant, "purchase-spend-release")
            .await?
            .ok_or("released recovery reservation missing")?
            .state,
        chio_finding_market_store_postgres::HostedSpendState::Released
    );
    Ok(())
}

/// A concurrent duplicate of an in-flight admission or reservation must
/// answer as a replay. Both paths probe before taking their per-tenant
/// serialization lock, so the loser observes a full tenant while its own
/// exact request is already durable; reporting capacity there would turn a
/// replay into a retryable error.
pub(super) async fn assert_concurrent_duplicates_replay(
    store: &PostgresFindingMarketStore,
    nonce: u128,
) -> Result<(), Box<dyn Error>> {
    // Two concurrent admissions of one proof race the capacity check. The
    // loser's exact request is durable by the time it observes a full
    // tenant, so it resumes that request rather than reporting a retryable
    // capacity error.
    let race_tenant = HostedTenantId::new(format!("integration-nonce-race-{nonce}"))?;
    store
        .register_tenant(
            &race_tenant,
            &HostedTenantLimits::new(1, 8, 10_000, "integration-revision-1")?,
            1_700_000_000,
        )
        .await?;
    let race_nonce = "1".repeat(64);
    let race_binding = "6".repeat(64);
    let (first_race, second_race) = tokio::join!(
        store.consume_capability_dpop_admission(
            &race_tenant,
            "capability-race",
            &race_nonce,
            Some(&race_binding),
            1_700_000_300,
            4,
            1_700_000_300,
            1_700_000_001,
            1,
        ),
        store.consume_capability_dpop_admission(
            &race_tenant,
            "capability-race",
            &race_nonce,
            Some(&race_binding),
            1_700_000_300,
            4,
            1_700_000_300,
            1_700_000_001,
            1,
        ),
    );
    let mut race_outcomes = vec![first_race?, second_race?];
    race_outcomes.sort_by_key(|outcome| format!("{outcome:?}"));
    assert_eq!(
        race_outcomes,
        vec![
            HostedCapabilityAdmissionOutcome::Admitted,
            HostedCapabilityAdmissionOutcome::RetriedSameRequest
        ],
        "a concurrent duplicate proof must resume its own request, never report capacity"
    );

    // The same invariant on the monthly spend period: the loser's identical
    // reservation is already durable and already charged, so it replays
    // instead of reporting the period as exhausted.
    let spend_race_tenant = HostedTenantId::new(format!("integration-spend-race-{nonce}"))?;
    store
        .register_tenant(
            &spend_race_tenant,
            &HostedTenantLimits::new(1, 8, 5_000, "integration-revision-1")?,
            1_700_000_000,
        )
        .await?;
    let (first_spend, second_spend) = tokio::join!(
        store.reserve_monthly_spend(&spend_race_tenant, "purchase-spend-race", 5_000),
        store.reserve_monthly_spend(&spend_race_tenant, "purchase-spend-race", 5_000),
    );
    let mut spend_outcomes = vec![first_spend?, second_spend?];
    spend_outcomes.sort_by_key(|outcome| format!("{outcome:?}"));
    assert_eq!(
        spend_outcomes,
        vec![
            HostedJobWriteOutcome::ExactReplay,
            HostedJobWriteOutcome::Inserted
        ],
        "a concurrent identical reservation must replay, not exhaust"
    );
    Ok(())
}

/// The admission and accounting invariants a hosted tenant depends on:
/// one invocation per request however many proofs carry it, a reissued
/// capability able to record its own admissions, a bound on what those
/// admissions retain, and accounting that denies rather than drifting.
pub(super) async fn assert_admission_and_accounting_invariants(
    store: &PostgresFindingMarketStore,
    runtime_pool: &sqlx::PgPool,
    admin_pool: &sqlx::PgPool,
    nonce: u128,
) -> Result<(), Box<dyn Error>> {
    assert_concurrent_fresh_proofs_spend_one_invocation(store, runtime_pool, nonce).await?;
    assert_one_proof_resumes_its_own_request(store, nonce).await?;
    assert_reissued_capability_records_its_admission(store, nonce).await?;
    assert_retained_request_bindings_are_bounded(store, nonce).await?;
    assert_charged_reservations_are_immutable(store, runtime_pool, nonce).await?;
    assert_spend_accumulator_underflow_denies(store, admin_pool, nonce).await
}

/// Concurrent retries of one request spend one invocation. Two fresh proofs
/// race with capacity and budget to spare, so no exhaustion check stops
/// either: only the admission record itself separates the retry from a
/// second request, and the invocation belongs to the request rather than to
/// the proof that carried it.
pub(super) async fn assert_concurrent_fresh_proofs_spend_one_invocation(
    store: &PostgresFindingMarketStore,
    runtime_pool: &sqlx::PgPool,
    nonce: u128,
) -> Result<(), Box<dyn Error>> {
    let tenant = &HostedTenantId::new(format!("integration-fresh-proof-race-{nonce}"))?;
    store
        .register_tenant(
            tenant,
            &HostedTenantLimits::new(1, 8, 10_000, "integration-revision-1")?,
            1_700_000_000,
        )
        .await?;
    let capability = "capability-fresh-proof-race";
    let binding = "5".repeat(64);
    let first_nonce = "a".repeat(64);
    let second_nonce = "b".repeat(64);
    let (first, second) = tokio::join!(
        store.consume_capability_dpop_admission(
            tenant,
            capability,
            &first_nonce,
            Some(&binding),
            1_700_000_300,
            4,
            1_700_000_300,
            1_700_000_001,
            8,
        ),
        store.consume_capability_dpop_admission(
            tenant,
            capability,
            &second_nonce,
            Some(&binding),
            1_700_000_300,
            4,
            1_700_000_300,
            1_700_000_001,
            8,
        ),
    );
    let mut outcomes = vec![first?, second?];
    outcomes.sort_by_key(|outcome| format!("{outcome:?}"));
    assert_eq!(
        outcomes,
        vec![
            HostedCapabilityAdmissionOutcome::Admitted,
            HostedCapabilityAdmissionOutcome::RetriedSameRequest
        ],
        "concurrent fresh proofs for one request must resolve to a single admission"
    );

    let mut reader = runtime_pool.begin().await?;
    sqlx::query("SELECT set_config('chio.tenant_id', $1, TRUE)")
        .bind(tenant.as_str())
        .execute(&mut *reader)
        .await?;
    let used: i64 = sqlx::query_scalar(
        "SELECT used_count FROM chio_finding_market_capability_uses WHERE tenant_id = $1 AND capability_id = $2",
    )
    .bind(tenant.as_str())
    .bind(capability)
    .fetch_one(&mut *reader)
    .await?;
    assert_eq!(
        used, 1,
        "one request must spend one invocation however many proofs carried it"
    );
    let live_nonces: i64 = sqlx::query_scalar(
        "SELECT live_nonces FROM chio_finding_market_dpop_admission_state WHERE tenant_id = $1",
    )
    .bind(tenant.as_str())
    .fetch_one(&mut *reader)
    .await?;
    assert_eq!(
        live_nonces, 1,
        "the losing proof must not consume a nonce slot of its own"
    );
    reader.commit().await?;
    Ok(())
}

/// A capability id reissued after its predecessor expired must be able to
/// record its own admissions. The expired record still holds the key until
/// a sweep removes it, and leaving its expiry in place would deny the very
/// retry the new admission is recording itself for.
pub(super) async fn assert_reissued_capability_records_its_admission(
    store: &PostgresFindingMarketStore,
    nonce: u128,
) -> Result<(), Box<dyn Error>> {
    let tenant = &HostedTenantId::new(format!("integration-reissued-capability-{nonce}"))?;
    store
        .register_tenant(
            tenant,
            &HostedTenantLimits::new(1, 8, 10_000, "integration-revision-1")?,
            1_700_000_000,
        )
        .await?;
    let capability = "capability-reissued";
    let binding = "4".repeat(64);
    assert_eq!(
        store
            .consume_capability_dpop_admission(
                tenant,
                capability,
                &"c".repeat(64),
                Some(&binding),
                1_700_000_100,
                1,
                1_700_000_100,
                1_700_000_001,
                8,
            )
            .await?,
        HostedCapabilityAdmissionOutcome::Admitted
    );

    // The authority reissues the same capability id past that expiry and
    // the same request arrives against it.
    assert_eq!(
        store
            .consume_capability_dpop_admission(
                tenant,
                capability,
                &"d".repeat(64),
                Some(&binding),
                1_700_000_600,
                1,
                1_700_000_600,
                1_700_000_200,
                8,
            )
            .await?,
        HostedCapabilityAdmissionOutcome::Admitted
    );

    // A retry of that request resumes it. Against the stale record it would
    // report the reissued capability's single invocation as exhausted.
    assert_eq!(
        store
            .consume_capability_dpop_admission(
                tenant,
                capability,
                &"e".repeat(64),
                Some(&binding),
                1_700_000_600,
                1,
                1_700_000_600,
                1_700_000_300,
                8,
            )
            .await?,
        HostedCapabilityAdmissionOutcome::RetriedSameRequest
    );
    Ok(())
}

/// A charged reservation records what it charged. Enlarging one in place
/// would leave the accumulator, and the ceiling enforced against it,
/// holding the original amount, so the write is refused outright.
pub(super) async fn assert_charged_reservations_are_immutable(
    store: &PostgresFindingMarketStore,
    runtime_pool: &sqlx::PgPool,
    nonce: u128,
) -> Result<(), Box<dyn Error>> {
    let tenant = &HostedTenantId::new(format!("integration-reservation-immutable-{nonce}"))?;
    store
        .register_tenant(
            tenant,
            &HostedTenantLimits::new(1, 8, 10_000, "integration-revision-1")?,
            1_700_000_000,
        )
        .await?;
    store
        .reserve_monthly_spend(tenant, "purchase-immutable", 1_000)
        .await?;

    let mut writer = runtime_pool.begin().await?;
    sqlx::query("SELECT set_config('chio.tenant_id', $1, TRUE)")
        .bind(tenant.as_str())
        .execute(&mut *writer)
        .await?;
    let enlarged = sqlx::query(
        "UPDATE chio_finding_market_spend_reservations SET units = 9000 WHERE tenant_id = $1 AND reservation_id = $2",
    )
    .bind(tenant.as_str())
    .bind("purchase-immutable")
    .execute(&mut *writer)
    .await;
    assert!(
        enlarged.is_err(),
        "a charged reservation must not be enlarged in place"
    );
    drop(writer);

    // The ceiling still reflects what was actually reserved.
    assert!(matches!(
        store
            .reserve_monthly_spend(tenant, "purchase-immutable-rest", 9_500)
            .await,
        Err(HostedMarketStoreError::Capacity)
    ));
    Ok(())
}

/// Retained request admissions are bounded. They outlive the proofs that
/// recorded them, so the live-proof ceiling does not bound them, and a
/// credential holder could otherwise rotate idempotency keys as its proof
/// slots expire and retain a row per admitted request.
pub(super) async fn assert_retained_request_bindings_are_bounded(
    store: &PostgresFindingMarketStore,
    nonce: u128,
) -> Result<(), Box<dyn Error>> {
    let tenant = &HostedTenantId::new(format!("integration-binding-ceiling-{nonce}"))?;
    store
        .register_tenant(
            tenant,
            &HostedTenantLimits::new(1, 8, 10_000, "integration-revision-1")?,
            1_700_000_000,
        )
        .await?;
    let capability = "capability-binding-ceiling";
    let expires_at = 1_700_100_000;
    // One live proof slot, so each admission's proof expires before the
    // next one and only the retained bindings accumulate.
    let capacity = 1;
    let ceiling = 64;
    let mut admitted = 0_u32;
    let mut refused = None;
    for index in 0..=ceiling {
        let at = 1_700_000_001 + i64::from(index) * 10;
        let outcome = store
            .consume_capability_dpop_admission(
                tenant,
                capability,
                &format!("{index:064x}"),
                Some(&format!("{:0>64}", format!("{index:x}b"))),
                u64::try_from(at + 5)?,
                200,
                expires_at,
                u64::try_from(at)?,
                capacity,
            )
            .await;
        match outcome {
            Ok(HostedCapabilityAdmissionOutcome::Admitted) => admitted += 1,
            Err(HostedMarketStoreError::Capacity) => {
                refused = Some(index);
                break;
            }
            other => panic!("unexpected admission outcome: {other:?}"),
        }
    }
    assert_eq!(
        refused,
        Some(ceiling),
        "the tenant must retain exactly its ceiling of request admissions"
    );
    assert_eq!(admitted, u32::try_from(ceiling)?);

    // The ceiling refuses new bindings rather than evicting recorded ones,
    // so every request already admitted stays recoverable.
    assert_eq!(
        store
            .consume_capability_dpop_admission(
                tenant,
                capability,
                &format!("{:064x}", 4_096),
                Some(&format!("{:0>64}", "0b")),
                1_700_000_800,
                200,
                expires_at,
                1_700_000_700,
                capacity,
            )
            .await?,
        HostedCapabilityAdmissionOutcome::RetriedSameRequest
    );
    Ok(())
}

/// Accounting that cannot be trusted denies rather than becoming
/// authoritative. Nothing re-derives the spend accumulator at runtime, so
/// clamping an underflow at zero would leave it undercounting the
/// reservations still charged and let later spend pass the ceiling.
pub(super) async fn assert_spend_accumulator_underflow_denies(
    store: &PostgresFindingMarketStore,
    admin_pool: &sqlx::PgPool,
    nonce: u128,
) -> Result<(), Box<dyn Error>> {
    let tenant = &HostedTenantId::new(format!("integration-spend-underflow-{nonce}"))?;
    store
        .register_tenant(
            tenant,
            &HostedTenantLimits::new(1, 8, 10_000, "integration-revision-1")?,
            1_700_000_000,
        )
        .await?;
    store
        .reserve_monthly_spend(tenant, "purchase-underflow-kept", 4_000)
        .await?;
    store
        .reserve_monthly_spend(tenant, "purchase-underflow-released", 4_000)
        .await?;

    // Only the owning role can write this accumulator now, so the skew a
    // partial repair would leave behind is injected with that role.
    let mut skew = admin_pool.begin().await?;
    let billing_period: String =
        sqlx::query_scalar("SELECT to_char(CURRENT_TIMESTAMP AT TIME ZONE 'UTC', 'YYYY-MM')")
            .fetch_one(&mut *skew)
            .await?;
    sqlx::query(
        "UPDATE chio_finding_market_spend_periods SET consumed_units = 1000 WHERE tenant_id = $1 AND billing_period = $2",
    )
    .bind(tenant.as_str())
    .bind(&billing_period)
    .execute(&mut *skew)
    .await?;
    skew.commit().await?;

    assert!(
        store
            .release_monthly_spend(tenant, "purchase-underflow-released")
            .await
            .is_err(),
        "a release that would drive the accumulator negative must deny"
    );

    let mut reader = admin_pool.begin().await?;
    let consumed: i64 = sqlx::query_scalar(
        "SELECT consumed_units FROM chio_finding_market_spend_periods WHERE tenant_id = $1 AND billing_period = $2",
    )
    .bind(tenant.as_str())
    .bind(&billing_period)
    .fetch_one(&mut *reader)
    .await?;
    assert_eq!(
        consumed, 1_000,
        "the denied release must leave the accumulator untouched rather than zeroed"
    );
    reader.commit().await?;
    Ok(())
}

/// Paging an aggregate's history must chain each page onto the caller's
/// anchor, end exactly at the durable head, and reject an anchor the chain
/// does not bind.
pub(super) async fn assert_paged_aggregate_history(
    store: &PostgresFindingMarketStore,
    tenant_a: &HostedTenantId,
    market_finding_id: &str,
) -> Result<(), Box<dyn Error>> {
    let first_page = store
        .aggregate_history_page(
            tenant_a,
            HostedAggregateKind::Finding,
            market_finding_id,
            0,
            None,
            1,
        )
        .await?;
    assert_eq!(first_page.events.len(), 1);
    assert_eq!(first_page.next_after_revision, Some(1));
    let second_page = store
        .aggregate_history_page(
            tenant_a,
            HostedAggregateKind::Finding,
            market_finding_id,
            1,
            Some(&first_page.events[0].event_sha256),
            1,
        )
        .await?;
    assert_eq!(second_page.events.len(), 1);
    assert_eq!(
        second_page.events[0].previous_event_sha256.as_deref(),
        Some(first_page.events[0].event_sha256.as_str()),
        "a page must chain onto its anchor"
    );
    assert_eq!(
        second_page.next_after_revision, None,
        "the page that reaches the head must end the walk"
    );
    assert!(
        matches!(
            store
                .aggregate_history_page(
                    tenant_a,
                    HostedAggregateKind::Finding,
                    market_finding_id,
                    1,
                    Some(&"0".repeat(64)),
                    1,
                )
                .await,
            Err(HostedMarketStoreError::DigestMismatch)
        ),
        "a page that does not chain onto the caller's anchor must fail closed"
    );
    Ok(())
}

/// A writer that predates the derived accumulators still keeps them
/// correct. The rollout applies migrations before the previous release is
/// replaced, so during that window a replica writes only the reservation
/// and nonce tables; both accumulators are trigger-maintained so the new
/// binary's capacity decisions still see those writes.
pub(super) async fn assert_prior_release_writes_keep_accumulators(
    store: &PostgresFindingMarketStore,
    runtime_pool: &sqlx::PgPool,
    nonce: u128,
) -> Result<(), Box<dyn Error>> {
    let tenant = &HostedTenantId::new(format!("integration-prior-release-{nonce}"))?;
    store
        .register_tenant(
            tenant,
            &HostedTenantLimits::new(1, 8, 5_000, "integration-revision-1")?,
            1_700_000_000,
        )
        .await?;
    let mut legacy = runtime_pool.begin().await?;
    sqlx::query("SELECT set_config('chio.tenant_id', $1, TRUE)")
        .bind(tenant.as_str())
        .execute(&mut *legacy)
        .await?;
    let billing_period: String =
        sqlx::query_scalar("SELECT to_char(CURRENT_TIMESTAMP AT TIME ZONE 'UTC', 'YYYY-MM')")
            .fetch_one(&mut *legacy)
            .await?;
    sqlx::query(
        "INSERT INTO chio_finding_market_spend_reservations (tenant_id, reservation_id, billing_period, units, state, created_at, updated_at) VALUES ($1, $2, $3, $4, 'reserved', $5, $5)",
    )
    .bind(tenant.as_str())
    .bind("purchase-spend-prior-release")
    .bind(&billing_period)
    .bind(3_000_i64)
    .bind(1_700_000_000_i64)
    .execute(&mut *legacy)
    .await?;
    sqlx::query(
        "INSERT INTO chio_finding_market_dpop_nonces (tenant_id, capability_id, nonce_sha256, valid_through, created_at) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(tenant.as_str())
    .bind("capability-prior-release")
    .bind("2".repeat(64))
    .bind(1_900_000_000_i64)
    .bind(1_700_000_000_i64)
    .execute(&mut *legacy)
    .await?;
    let consumed: i64 = sqlx::query_scalar(
        "SELECT consumed_units FROM chio_finding_market_spend_periods WHERE tenant_id = $1 AND billing_period = $2",
    )
    .bind(tenant.as_str())
    .bind(&billing_period)
    .fetch_one(&mut *legacy)
    .await?;
    assert_eq!(
        consumed, 3_000,
        "a reservation written by the previous release must charge the period"
    );
    let live_nonces: i64 = sqlx::query_scalar(
        "SELECT live_nonces FROM chio_finding_market_dpop_admission_state WHERE tenant_id = $1",
    )
    .bind(tenant.as_str())
    .fetch_one(&mut *legacy)
    .await?;
    assert_eq!(
        live_nonces, 1,
        "a nonce written by the previous release must count against the tenant"
    );
    legacy.commit().await?;

    assert!(
        matches!(
            store
                .reserve_monthly_spend(tenant, "purchase-spend-over-prior", 3_000)
                .await,
            Err(HostedMarketStoreError::Capacity)
        ),
        "the ceiling must account for the previous release's reservation"
    );
    assert!(
        matches!(
            store
                .consume_capability_dpop_admission(
                    tenant,
                    "capability-after-prior-release",
                    &"3".repeat(64),
                    Some(&"9".repeat(64)),
                    1_900_000_000,
                    4,
                    1_900_000_000,
                    1_700_000_001,
                    1,
                )
                .await,
            Err(HostedMarketStoreError::Capacity)
        ),
        "the nonce ceiling must account for the previous release's nonce"
    );
    Ok(())
}

/// Re-presenting one proof for the request it was admitted for resumes,
/// and the same proof for any other request stays a replay.
///
/// This runs sequentially, so it resolves on the ledger probe that opens
/// the admission rather than on the live-nonce probe below it. The raced
/// ordering, where an attempt passes the ledger probe before a concurrent
/// winner commits and then finds the nonce live, is covered by
/// [`assert_concurrent_duplicates_replay`]; it cannot be reached
/// deterministically without a pause between the two probes.
pub(super) async fn assert_one_proof_resumes_its_own_request(
    store: &PostgresFindingMarketStore,
    nonce: u128,
) -> Result<(), Box<dyn Error>> {
    let tenant = &HostedTenantId::new(format!("integration-proof-resume-{nonce}"))?;
    store
        .register_tenant(
            tenant,
            &HostedTenantLimits::new(1, 8, 10_000, "integration-revision-1")?,
            1_700_000_000,
        )
        .await?;
    let capability = "capability-proof-resume";
    let proof = "7".repeat(64);
    let binding = "8".repeat(64);
    let admit = |at: u64| {
        store.consume_capability_dpop_admission(
            tenant,
            capability,
            &proof,
            Some(&binding),
            1_700_000_300,
            4,
            1_700_000_300,
            at,
            8,
        )
    };
    assert_eq!(
        admit(1_700_000_001).await?,
        HostedCapabilityAdmissionOutcome::Admitted
    );
    assert_eq!(
        admit(1_700_000_002).await?,
        HostedCapabilityAdmissionOutcome::RetriedSameRequest,
        "the proof's own request must resume rather than be rejected as a replay"
    );
    // The same live proof presented for a different request stays a
    // replay: the binding, not the nonce, is what may be resumed.
    assert_eq!(
        store
            .consume_capability_dpop_admission(
                tenant,
                capability,
                &proof,
                Some(&"9".repeat(64)),
                1_700_000_300,
                4,
                1_700_000_300,
                1_700_000_003,
                8,
            )
            .await?,
        HostedCapabilityAdmissionOutcome::Replay
    );
    Ok(())
}

/// A proof is bound to the exact request it authorized. An identical retry
/// resumes that request, which is what lets a mutation cut short after
/// admission complete; the same nonce presented for any other request is a
/// replay and denies.
pub(super) async fn assert_admission_binds_its_request(
    store: &PostgresFindingMarketStore,
    tenant: &HostedTenantId,
    nonce: &str,
    binding: &str,
) -> Result<(), Box<dyn Error>> {
    // A mutation cut short after admission resumes on an identical retry,
    // including one carrying a fresh proof: the record of the admitted
    // request outlives the nonce that created it, so recovery is not
    // bounded by proof freshness. It costs no further invocation.
    assert_eq!(
        store
            .consume_capability_dpop_admission(
                tenant,
                "capability-atomic",
                &"b".repeat(64),
                Some(binding),
                1_700_000_300,
                2,
                1_700_000_300,
                1_700_000_005,
                8,
            )
            .await?,
        HostedCapabilityAdmissionOutcome::RetriedSameRequest
    );
    // The same nonce presented for any other request is still a replay.
    assert_eq!(
        store
            .consume_capability_dpop_admission(
                tenant,
                "capability-atomic",
                nonce,
                Some(&"9".repeat(64)),
                1_700_000_300,
                2,
                1_700_000_300,
                1_700_000_006,
                8,
            )
            .await?,
        HostedCapabilityAdmissionOutcome::Replay
    );
    // A request with no idempotency key records nothing, so reusing its
    // proof stays a rejected replay rather than a free repeat.
    let read_capability = "capability-read-only";
    let read_nonce = "7".repeat(64);
    assert_eq!(
        store
            .consume_capability_dpop_admission(
                tenant,
                read_capability,
                &read_nonce,
                None,
                1_700_000_300,
                4,
                1_700_000_300,
                1_700_000_007,
                8,
            )
            .await?,
        HostedCapabilityAdmissionOutcome::Admitted
    );
    assert_eq!(
        store
            .consume_capability_dpop_admission(
                tenant,
                read_capability,
                &read_nonce,
                None,
                1_700_000_300,
                4,
                1_700_000_300,
                1_700_000_008,
                8,
            )
            .await?,
        HostedCapabilityAdmissionOutcome::Replay
    );
    Ok(())
}
