use super::*;

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
