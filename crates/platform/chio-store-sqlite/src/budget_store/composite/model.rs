use super::*;
use rusqlite::{params, OptionalExtension, Transaction};

/// Upper bound for a supplemental authorization expiry, in seconds since the Unix
/// epoch (2100-01-01T00:00:00Z). Capture compares the expiry against SQLite's
/// `unixepoch()`, which is also seconds, so a millisecond-shaped value would never
/// expire against that clock. Such values are rejected rather than accepted.
pub(super) const MAX_SUPPLEMENTAL_AUTHORIZATION_EXPIRES_AT_SECONDS: u64 = 4_102_444_800;

#[derive(Clone)]
pub(super) struct QuotaState {
    pub(super) quota: BudgetInvocationQuota,
    pub(super) maximum: u32,
    pub(super) reserved: u32,
    pub(super) captured: u32,
    pub(super) version: u64,
}

impl QuotaState {
    pub(super) fn new(quota: &BudgetInvocationQuota) -> Self {
        Self {
            quota: quota.clone(),
            maximum: quota.max_invocations,
            reserved: 0,
            captured: 0,
            version: 0,
        }
    }

    pub(super) fn usage(&self) -> BudgetInvocationQuotaUsage {
        BudgetInvocationQuotaUsage {
            quota: self.quota.clone(),
            reserved_invocations: self.reserved,
            captured_invocations: self.captured,
        }
    }
}

#[derive(Clone)]
pub(super) struct CumulativeAccount {
    pub(super) key: BudgetCumulativeApprovalAccountKey,
    pub(super) root_grant_hash: String,
    pub(super) delegation_root_id: Option<String>,
    pub(super) root_binding_digest: Option<String>,
    pub(super) currency: String,
    pub(super) authority_threshold: u64,
    pub(super) reserved: u64,
    pub(super) captured: u64,
    pub(super) version: u64,
}

#[derive(Clone)]
pub(super) struct StructuredHold {
    pub(super) hold_id: String,
    pub(super) capability_id: String,
    pub(super) grant_index: usize,
    pub(super) admission: BudgetAdmissionBinding,
    pub(super) invocation_state: BudgetInvocationState,
    pub(super) monetary_state: BudgetMonetaryState,
    pub(super) authorized_exposure: u64,
    pub(super) remaining_exposure: u64,
    pub(super) authority: Option<BudgetEventAuthority>,
    pub(super) quotas: Vec<BudgetInvocationQuota>,
    pub(super) cumulative: Option<(
        BudgetCumulativeApprovalRequest,
        BudgetCumulativeApprovalState,
        Option<String>,
    )>,
}

pub(super) fn normalized_quotas(
    request: &BudgetAuthorizeHoldRequest,
) -> Result<Vec<BudgetInvocationQuota>, BudgetStoreError> {
    if !request.invocation_quotas.is_empty() {
        return Ok(request.invocation_quotas.clone());
    }
    request
        .max_invocations
        .map(|maximum| {
            Ok(vec![BudgetInvocationQuota {
                key: BudgetQuotaKey::grant(
                    request.capability_id.clone(),
                    u32::try_from(request.grant_index).map_err(|_| {
                        BudgetStoreError::Invariant("grant_index does not fit u32".to_string())
                    })?,
                ),
                max_invocations: maximum,
            }])
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

pub(super) fn validate_composite_sqlite_range(
    request: &BudgetAuthorizeHoldRequest,
    quotas: &[BudgetInvocationQuota],
) -> Result<(), BudgetStoreError> {
    validate_budget_grant_index(request.grant_index)?;
    budget_u64_to_sqlite(request.requested_exposure_units, "requested_exposure_units")?;
    optional_budget_u64_to_sqlite(request.max_cost_per_invocation, "max_cost_per_invocation")?;
    optional_budget_u64_to_sqlite(request.max_total_cost_units, "max_total_cost_units")?;
    if let Some(authority) = &request.authority {
        budget_u64_to_sqlite(authority.lease_epoch, "lease_epoch")?;
    }
    if let Some(binding) = &request.admission_binding {
        if let Some(commit) = binding.last_observed_revocation.as_ref() {
            budget_u64_to_sqlite(commit.authority.lease_epoch, "revocation_lease_epoch")?;
            budget_u64_to_sqlite(commit.commit_index, "revocation_commit_index")?;
        }
        optional_budget_u64_to_sqlite(
            binding.supplemental_authorization_expires_at,
            "supplemental_expires_at",
        )?;
        if binding.supplemental_authorization_expires_at == Some(0) {
            return Err(BudgetStoreError::Invariant(
                "supplemental authorization expiry must be positive".to_string(),
            ));
        }
        if binding
            .supplemental_authorization_expires_at
            .is_some_and(|expires_at| {
                expires_at > MAX_SUPPLEMENTAL_AUTHORIZATION_EXPIRES_AT_SECONDS
            })
        {
            return Err(BudgetStoreError::Invariant(
                "supplemental authorization expiry is not expressed in seconds".to_string(),
            ));
        }
    }
    for quota in quotas {
        let _ = quota_index(&quota.key)?;
    }
    if let Some(cumulative) = &request.cumulative_approval {
        for (value, field) in [
            (
                cumulative.account_key.approval_budget_epoch,
                "approval_budget_epoch",
            ),
            (
                cumulative.authority_threshold.units,
                "authority_threshold_units",
            ),
            (
                cumulative.effective_threshold.units,
                "effective_threshold_units",
            ),
            (
                cumulative.requested_authorized.units,
                "requested_authorized_units",
            ),
        ] {
            budget_u64_to_sqlite(value, field)?;
        }
    }
    Ok(())
}

pub(super) fn quota_index(key: &BudgetQuotaKey) -> Result<i64, BudgetStoreError> {
    match (key.profile, key.grant_index) {
        (BudgetQuotaProfile::GrantInvocation, Some(index)) => Ok(i64::from(index)),
        (BudgetQuotaProfile::GrantInvocation, None) => Err(BudgetStoreError::Invariant(
            "grant quota is missing grant_index".to_string(),
        )),
        (_, None) => Ok(-1),
        (_, Some(_)) => Err(BudgetStoreError::Invariant(
            "non-grant quota carries grant_index".to_string(),
        )),
    }
}

pub(super) fn quota_key(
    profile: &str,
    owner_id: String,
    index: i64,
) -> Result<BudgetQuotaKey, BudgetStoreError> {
    let profile = BudgetQuotaProfile::parse(profile)
        .ok_or_else(|| BudgetStoreError::Invariant(format!("unknown quota profile `{profile}`")))?;
    let grant_index =
        if index == -1 {
            None
        } else {
            Some(u32::try_from(index).map_err(|_| {
                BudgetStoreError::Invariant("invalid quota grant_index".to_string())
            })?)
        };
    Ok(BudgetQuotaKey {
        profile,
        owner_id,
        grant_index,
    })
}

pub(super) fn load_usage_or_default(
    transaction: &Transaction<'_>,
    capability_id: &str,
    grant_index: usize,
) -> Result<BudgetUsageRecord, BudgetStoreError> {
    validate_budget_grant_index(grant_index)?;
    let row = transaction
        .query_row(
            r#"
            SELECT invocation_count, updated_at, seq,
                   total_cost_exposed, total_cost_realized_spend
            FROM capability_grant_budgets
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![capability_id, grant_index as i64],
            |row| {
                Ok((
                    budget_u32_from_row(row, 0, "invocation_count")?,
                    row.get::<_, i64>(1)?,
                    budget_u64_from_row(row, 2, "seq")?,
                    budget_u64_from_row(row, 3, "total_cost_exposed")?,
                    budget_u64_from_row(row, 4, "total_cost_realized_spend")?,
                ))
            },
        )
        .optional()?;
    let grant_index = u32::try_from(grant_index)
        .map_err(|_| BudgetStoreError::Invariant("grant_index does not fit u32".to_string()))?;
    Ok(row.map_or(
        BudgetUsageRecord {
            capability_id: capability_id.to_string(),
            grant_index,
            invocation_count: 0,
            updated_at: unix_now(),
            seq: 0,
            total_cost_exposed: 0,
            total_cost_realized_spend: 0,
        },
        |row| BudgetUsageRecord {
            capability_id: capability_id.to_string(),
            grant_index,
            invocation_count: row.0,
            updated_at: row.1,
            seq: row.2,
            total_cost_exposed: row.3,
            total_cost_realized_spend: row.4,
        },
    ))
}

pub(super) fn write_usage(
    transaction: &Transaction<'_>,
    usage: &BudgetUsageRecord,
) -> Result<(), BudgetStoreError> {
    transaction.execute(
        r#"
        INSERT INTO capability_grant_budgets (
            capability_id, grant_index, invocation_count, updated_at, seq,
            total_cost_exposed, total_cost_realized_spend
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(capability_id, grant_index) DO UPDATE SET
            invocation_count = excluded.invocation_count,
            updated_at = excluded.updated_at,
            seq = excluded.seq,
            total_cost_exposed = excluded.total_cost_exposed,
            total_cost_realized_spend = excluded.total_cost_realized_spend
        "#,
        params![
            &usage.capability_id,
            i64::from(usage.grant_index),
            i64::from(usage.invocation_count),
            usage.updated_at,
            budget_u64_to_sqlite(usage.seq, "seq")?,
            budget_u64_to_sqlite(usage.total_cost_exposed, "total_cost_exposed")?,
            budget_u64_to_sqlite(usage.total_cost_realized_spend, "total_cost_realized_spend",)?,
        ],
    )?;
    Ok(())
}

pub(super) fn load_quota_state(
    transaction: &Transaction<'_>,
    key: &BudgetQuotaKey,
) -> Result<Option<QuotaState>, BudgetStoreError> {
    transaction
        .query_row(
            r#"
            SELECT max_invocations, reserved_invocations,
                   captured_invocations, version
            FROM budget_invocation_quotas
            WHERE profile = ?1 AND owner_id = ?2 AND grant_index = ?3
            "#,
            params![key.profile.as_str(), &key.owner_id, quota_index(key)?],
            |row| {
                Ok((
                    budget_u32_from_row(row, 0, "max_invocations")?,
                    budget_u32_from_row(row, 1, "reserved_invocations")?,
                    budget_u32_from_row(row, 2, "captured_invocations")?,
                    budget_u64_from_row(row, 3, "version")?,
                ))
            },
        )
        .optional()?
        .map(|row| {
            Ok(QuotaState {
                quota: BudgetInvocationQuota {
                    key: key.clone(),
                    max_invocations: row.0,
                },
                maximum: row.0,
                reserved: row.1,
                captured: row.2,
                version: row.3,
            })
        })
        .transpose()
}

pub(super) fn legacy_grant_quota_limit(
    transaction: &Transaction<'_>,
    capability_id: &str,
    grant_index: usize,
) -> Result<Option<u32>, BudgetStoreError> {
    validate_budget_grant_index(grant_index)?;
    let row = transaction.query_row(
        r#"
        SELECT MIN(max_invocations), MAX(max_invocations),
               COUNT(DISTINCT max_invocations)
        FROM budget_mutation_events
        WHERE capability_id = ?1 AND grant_index = ?2
          AND projection_kind = 'legacy' AND max_invocations IS NOT NULL
        "#,
        params![capability_id, grant_index as i64],
        |row| {
            Ok((
                row.get::<_, Option<i64>>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        },
    )?;
    if row.2 > 1 || row.0 != row.1 {
        return Err(BudgetStoreError::Invariant(format!(
            "legacy grant quota for `{capability_id}` grant {grant_index} is inconsistent"
        )));
    }
    row.0
        .map(|maximum| {
            u32::try_from(maximum).map_err(|_| {
                BudgetStoreError::Invariant(format!(
                    "legacy grant quota for `{capability_id}` grant {grant_index} is outside u32 range"
                ))
            })
        })
        .transpose()
}

pub(super) fn write_quota_state(
    transaction: &Transaction<'_>,
    state: &QuotaState,
) -> Result<(), BudgetStoreError> {
    let changed = transaction.execute(
        r#"
        INSERT INTO budget_invocation_quotas (
            profile, owner_id, grant_index, max_invocations,
            reserved_invocations, captured_invocations, version
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(profile, owner_id, grant_index) DO UPDATE SET
            reserved_invocations = excluded.reserved_invocations,
            captured_invocations = excluded.captured_invocations,
            version = excluded.version
        WHERE budget_invocation_quotas.max_invocations = excluded.max_invocations
        "#,
        params![
            state.quota.key.profile.as_str(),
            &state.quota.key.owner_id,
            quota_index(&state.quota.key)?,
            i64::from(state.maximum),
            i64::from(state.reserved),
            i64::from(state.captured),
            budget_u64_to_sqlite(state.version, "quota_version")?,
        ],
    )?;
    if changed != 1 {
        return Err(BudgetStoreError::Invariant(format!(
            "budget quota `{}` immutable maximum changed",
            state.quota.key.owner_id
        )));
    }
    Ok(())
}

pub(super) fn write_hold_quota(
    transaction: &Transaction<'_>,
    hold_id: &str,
    quota: &BudgetInvocationQuota,
) -> Result<(), BudgetStoreError> {
    transaction.execute(
        r#"
        INSERT INTO budget_hold_quota_members (
            hold_id, profile, owner_id, grant_index, max_invocations
        ) VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
        params![
            hold_id,
            quota.key.profile.as_str(),
            &quota.key.owner_id,
            quota_index(&quota.key)?,
            i64::from(quota.max_invocations),
        ],
    )?;
    Ok(())
}

pub(super) fn load_or_validate_cumulative(
    transaction: &Transaction<'_>,
    request: &BudgetCumulativeApprovalRequest,
) -> Result<CumulativeAccount, BudgetStoreError> {
    let key = &request.account_key;
    let row = transaction
        .query_row(
            r#"
            SELECT root_grant_hash, delegation_root_id, root_binding_digest,
                   currency, authority_threshold_units,
                   reserved_authorized_units, captured_authorized_units, version
            FROM budget_cumulative_approval_accounts
            WHERE authority_id = ?1 AND owner_id = ?2
              AND approval_budget_id = ?3 AND approval_budget_epoch = ?4
            "#,
            params![
                &key.authority_id,
                &key.owner_id,
                &key.approval_budget_id,
                budget_u64_to_sqlite(key.approval_budget_epoch, "approval_budget_epoch")?,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    budget_u64_from_row(row, 4, "authority_threshold_units")?,
                    budget_u64_from_row(row, 5, "reserved_authorized_units")?,
                    budget_u64_from_row(row, 6, "captured_authorized_units")?,
                    budget_u64_from_row(row, 7, "version")?,
                ))
            },
        )
        .optional()?;
    if let Some(row) = row {
        if row.0 != key.root_grant_hash
            || row.1 != key.delegation_root_id
            || row.2 != key.root_binding_digest
            || row.3 != key.currency
            || row.4 != request.authority_threshold.units
        {
            return Err(BudgetStoreError::Invariant(
                "cumulative approval account immutable authority changed".to_string(),
            ));
        }
        return Ok(CumulativeAccount {
            key: key.clone(),
            root_grant_hash: row.0,
            delegation_root_id: row.1,
            root_binding_digest: row.2,
            currency: row.3,
            authority_threshold: row.4,
            reserved: row.5,
            captured: row.6,
            version: row.7,
        });
    }
    Ok(CumulativeAccount {
        key: key.clone(),
        root_grant_hash: key.root_grant_hash.clone(),
        delegation_root_id: key.delegation_root_id.clone(),
        root_binding_digest: key.root_binding_digest.clone(),
        currency: key.currency.clone(),
        authority_threshold: request.authority_threshold.units,
        reserved: 0,
        captured: 0,
        version: 0,
    })
}

pub(super) fn write_cumulative_account(
    transaction: &Transaction<'_>,
    account: &CumulativeAccount,
) -> Result<(), BudgetStoreError> {
    let changed = transaction.execute(
        r#"
        INSERT INTO budget_cumulative_approval_accounts (
            authority_id, owner_id, approval_budget_id, approval_budget_epoch,
            root_grant_hash, delegation_root_id, root_binding_digest, currency,
            authority_threshold_units, reserved_authorized_units,
            captured_authorized_units, version
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        ON CONFLICT(authority_id, owner_id, approval_budget_id, approval_budget_epoch)
        DO UPDATE SET
            reserved_authorized_units = excluded.reserved_authorized_units,
            captured_authorized_units = excluded.captured_authorized_units,
            version = excluded.version
        WHERE budget_cumulative_approval_accounts.root_grant_hash = excluded.root_grant_hash
          AND budget_cumulative_approval_accounts.delegation_root_id IS excluded.delegation_root_id
          AND budget_cumulative_approval_accounts.root_binding_digest IS excluded.root_binding_digest
          AND budget_cumulative_approval_accounts.currency = excluded.currency
          AND budget_cumulative_approval_accounts.authority_threshold_units = excluded.authority_threshold_units
        "#,
        params![
            &account.key.authority_id,
            &account.key.owner_id,
            &account.key.approval_budget_id,
            budget_u64_to_sqlite(
                account.key.approval_budget_epoch,
                "approval_budget_epoch",
            )?,
            &account.root_grant_hash,
            account.delegation_root_id.as_deref(),
            account.root_binding_digest.as_deref(),
            &account.currency,
            budget_u64_to_sqlite(account.authority_threshold, "authority_threshold_units")?,
            budget_u64_to_sqlite(account.reserved, "reserved_authorized_units")?,
            budget_u64_to_sqlite(account.captured, "captured_authorized_units")?,
            budget_u64_to_sqlite(account.version, "cumulative_account_version")?,
        ],
    )?;
    if changed != 1 {
        return Err(BudgetStoreError::Invariant(
            "cumulative approval account immutable authority changed".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn write_cumulative_operation(
    transaction: &Transaction<'_>,
    hold_id: &str,
    request: &BudgetCumulativeApprovalRequest,
    state: BudgetCumulativeApprovalState,
    account_version: u64,
) -> Result<(), BudgetStoreError> {
    transaction.execute(
        r#"
        INSERT INTO budget_cumulative_approval_operations (
            operation_id, hold_id, authority_id, owner_id, approval_budget_id,
            approval_budget_epoch, effective_threshold_units,
            requested_authorized_units, state, account_version
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        "#,
        params![
            &request.operation_id,
            hold_id,
            &request.account_key.authority_id,
            &request.account_key.owner_id,
            &request.account_key.approval_budget_id,
            budget_u64_to_sqlite(
                request.account_key.approval_budget_epoch,
                "approval_budget_epoch",
            )?,
            budget_u64_to_sqlite(
                request.effective_threshold.units,
                "effective_threshold_units",
            )?,
            budget_u64_to_sqlite(
                request.requested_authorized.units,
                "requested_authorized_units",
            )?,
            cumulative_state_text(state),
            budget_u64_to_sqlite(account_version, "cumulative_account_version")?,
        ],
    )?;
    Ok(())
}

pub(super) fn write_hold_projection(
    transaction: &Transaction<'_>,
    hold_id: &str,
    admission: &BudgetAdmissionBinding,
    expected_quota_count: usize,
    cumulative_state: Option<BudgetCumulativeApprovalState>,
    exposure: u64,
) -> Result<(), BudgetStoreError> {
    let monetary = if exposure == 0 { "none" } else { "exposed" };
    transaction.execute(
        r#"
        UPDATE budget_authorization_holds
        SET projection_kind = 'composite_v1',
            operation_id = ?2,
            revocation_set_digest = ?3,
            expected_quota_count = ?4,
            expected_artifact_count = ?5,
            has_cumulative_approval = ?6,
            has_revocation_commit = ?7,
            authorization_outcome = ?8,
            invocation_state = 'authorized',
            monetary_state = ?9,
            supplemental_verifier_id = ?10,
            supplemental_verifier_config_digest = ?11,
            supplemental_artifact_digest = ?12,
            supplemental_expires_at = ?13,
            expected_revocation_count = ?14
        WHERE hold_id = ?1
        "#,
        params![
            hold_id,
            &admission.operation_id,
            admission.revocation_set.digest(),
            i64::try_from(expected_quota_count).map_err(|_| BudgetStoreError::Invariant(
                "quota count exceeds sqlite range".to_string()
            ))?,
            i64::try_from(admission.authorization_artifact_digests.len()).map_err(|_| {
                BudgetStoreError::Invariant("artifact count exceeds sqlite range".to_string())
            })?,
            cumulative_state.is_some(),
            admission.last_observed_revocation.is_some(),
            if cumulative_state == Some(BudgetCumulativeApprovalState::PendingApproval) {
                "approval_required"
            } else {
                "authorized"
            },
            monetary,
            admission.supplemental_verifier_id.as_deref(),
            admission.supplemental_verifier_config_digest.as_deref(),
            admission
                .supplemental_authorization_artifact_digest
                .as_deref(),
            optional_budget_u64_to_sqlite(
                admission.supplemental_authorization_expires_at,
                "supplemental_expires_at",
            )?,
            i64::try_from(admission.revocation_set.ids().len()).map_err(|_| {
                BudgetStoreError::Invariant("revocation count exceeds sqlite range".to_string())
            })?,
        ],
    )?;
    Ok(())
}

pub(super) fn write_hold_admission_members(
    transaction: &Transaction<'_>,
    hold_id: &str,
    admission: &BudgetAdmissionBinding,
) -> Result<(), BudgetStoreError> {
    for (index, capability_id) in admission.revocation_set.ids().iter().enumerate() {
        transaction.execute(
            r#"
            INSERT INTO budget_hold_revocation_members (
                hold_id, member_index, capability_id
            ) VALUES (?1, ?2, ?3)
            "#,
            params![hold_id, index as i64, capability_id],
        )?;
    }
    for (index, digest) in admission.authorization_artifact_digests.iter().enumerate() {
        transaction.execute(
            r#"
            INSERT INTO budget_hold_authorization_artifacts (
                hold_id, artifact_index, artifact_digest
            ) VALUES (?1, ?2, ?3)
            "#,
            params![hold_id, index as i64, digest],
        )?;
    }
    write_hold_revocation_commit(
        transaction,
        hold_id,
        admission.last_observed_revocation.as_ref(),
    )?;
    Ok(())
}

fn revocation_guarantee(value: &str) -> Result<BudgetGuaranteeLevel, BudgetStoreError> {
    match value {
        "single_node_atomic" => Ok(BudgetGuaranteeLevel::SingleNodeAtomic),
        "ha_linearizable" => Ok(BudgetGuaranteeLevel::HaLinearizable),
        _ => Err(BudgetStoreError::Invariant(format!(
            "invalid revocation guarantee level `{value}`"
        ))),
    }
}

fn write_hold_revocation_commit(
    transaction: &Transaction<'_>,
    hold_id: &str,
    commit: Option<&RevocationCommitMetadata>,
) -> Result<(), BudgetStoreError> {
    if let Some(commit) = commit {
        transaction.execute(
            r#"
            INSERT INTO budget_hold_revocation_commits (
                hold_id, authority_id, lease_id, lease_epoch,
                guarantee_level, commit_index
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                hold_id,
                &commit.authority.authority_id,
                &commit.authority.lease_id,
                budget_u64_to_sqlite(commit.authority.lease_epoch, "revocation_lease_epoch")?,
                commit.guarantee_level.as_str(),
                budget_u64_to_sqlite(commit.commit_index, "revocation_commit_index")?,
            ],
        )?;
    }
    Ok(())
}

pub(super) fn write_event_revocation_commit(
    transaction: &Transaction<'_>,
    event_id: &str,
    commit: Option<&RevocationCommitMetadata>,
) -> Result<(), BudgetStoreError> {
    if let Some(commit) = commit {
        transaction.execute(
            r#"
            INSERT INTO budget_event_revocation_commits (
                event_id, authority_id, lease_id, lease_epoch,
                guarantee_level, commit_index
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                event_id,
                &commit.authority.authority_id,
                &commit.authority.lease_id,
                budget_u64_to_sqlite(commit.authority.lease_epoch, "revocation_lease_epoch")?,
                commit.guarantee_level.as_str(),
                budget_u64_to_sqlite(commit.commit_index, "revocation_commit_index")?,
            ],
        )?;
    }
    Ok(())
}

fn revocation_commit_from_row(
    row: (String, String, i64, String, i64),
) -> Result<RevocationCommitMetadata, BudgetStoreError> {
    Ok(RevocationCommitMetadata {
        authority: BudgetEventAuthority {
            authority_id: row.0,
            lease_id: row.1,
            lease_epoch: u64::try_from(row.2).map_err(|_| {
                BudgetStoreError::Invariant("negative revocation lease epoch".to_string())
            })?,
        },
        guarantee_level: revocation_guarantee(&row.3)?,
        commit_index: u64::try_from(row.4).map_err(|_| {
            BudgetStoreError::Invariant("negative revocation commit index".to_string())
        })?,
    })
}

fn load_hold_revocation_commit(
    transaction: &Transaction<'_>,
    hold_id: &str,
) -> Result<Option<RevocationCommitMetadata>, BudgetStoreError> {
    let commit = transaction
        .query_row(
            r#"
            SELECT authority_id, lease_id, lease_epoch, guarantee_level, commit_index
            FROM budget_hold_revocation_commits WHERE hold_id = ?1
            "#,
            params![hold_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?
        .map(revocation_commit_from_row)
        .transpose()?;
    if let Some(commit) = commit.as_ref() {
        crate::serving_owner::verify_historical_revocation_commit(transaction, commit)?;
    }
    Ok(commit)
}

pub(super) fn load_event_revocation_commit(
    transaction: &Transaction<'_>,
    event_id: &str,
) -> Result<Option<RevocationCommitMetadata>, BudgetStoreError> {
    let commit = transaction
        .query_row(
            r#"
            SELECT authority_id, lease_id, lease_epoch, guarantee_level, commit_index
            FROM budget_event_revocation_commits WHERE event_id = ?1
            "#,
            params![event_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?
        .map(revocation_commit_from_row)
        .transpose()?;
    if let Some(commit) = commit.as_ref() {
        crate::serving_owner::verify_historical_revocation_commit(transaction, commit)?;
    }
    Ok(commit)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn write_authorization_event_projection(
    transaction: &Transaction<'_>,
    event_id: &str,
    admission: &BudgetAdmissionBinding,
    outcome: BudgetAuthorizationOutcome,
    quotas: &[BudgetInvocationQuota],
    quota_before: &[QuotaState],
    quota_after: &[QuotaState],
    cumulative: Option<&BudgetCumulativeApprovalRequest>,
    cumulative_state: Option<BudgetCumulativeApprovalState>,
    cumulative_before: Option<&CumulativeAccount>,
    cumulative_after: Option<&CumulativeAccount>,
    invocation_quotas_explicit: bool,
    requested_exposure_units: u64,
) -> Result<(), BudgetStoreError> {
    transaction.execute(
        r#"
        UPDATE budget_mutation_events
        SET projection_kind = 'composite_v1',
            operation_id = ?2,
            revocation_set_digest = ?3,
            expected_quota_count = ?4,
            expected_artifact_count = ?5,
            has_cumulative_approval = ?6,
            has_revocation_commit = ?7,
            authorization_outcome = ?8,
            invocation_state_before = 'absent',
            invocation_state_after = ?9,
            monetary_state_before = 'none',
            monetary_state_after = ?10,
            supplemental_verifier_id = ?11,
            supplemental_verifier_config_digest = ?12,
            supplemental_artifact_digest = ?13,
            supplemental_expires_at = ?14,
            invocation_quotas_explicit = ?15,
            expected_revocation_count = ?16
        WHERE event_id = ?1
        "#,
        params![
            event_id,
            &admission.operation_id,
            admission.revocation_set.digest(),
            i64::try_from(quotas.len()).map_err(|_| {
                BudgetStoreError::Invariant("quota count exceeds sqlite range".to_string())
            })?,
            i64::try_from(admission.authorization_artifact_digests.len()).map_err(|_| {
                BudgetStoreError::Invariant("artifact count exceeds sqlite range".to_string())
            })?,
            cumulative.is_some(),
            admission.last_observed_revocation.is_some(),
            budget_authorization_outcome_text(outcome),
            if outcome == BudgetAuthorizationOutcome::Denied {
                "denied"
            } else {
                "authorized"
            },
            if outcome == BudgetAuthorizationOutcome::Denied {
                "none"
            } else if requested_exposure_units > 0 {
                "exposed"
            } else {
                "none"
            },
            admission.supplemental_verifier_id.as_deref(),
            admission.supplemental_verifier_config_digest.as_deref(),
            admission
                .supplemental_authorization_artifact_digest
                .as_deref(),
            optional_budget_u64_to_sqlite(
                admission.supplemental_authorization_expires_at,
                "supplemental_expires_at",
            )?,
            invocation_quotas_explicit,
            i64::try_from(admission.revocation_set.ids().len()).map_err(|_| {
                BudgetStoreError::Invariant("revocation count exceeds sqlite range".to_string())
            })?,
        ],
    )?;
    for (index, capability_id) in admission.revocation_set.ids().iter().enumerate() {
        transaction.execute(
            r#"
            INSERT INTO budget_event_revocation_members (
                event_id, member_index, capability_id
            ) VALUES (?1, ?2, ?3)
            "#,
            params![event_id, index as i64, capability_id],
        )?;
    }
    for (index, digest) in admission.authorization_artifact_digests.iter().enumerate() {
        transaction.execute(
            r#"
            INSERT INTO budget_event_authorization_artifacts (
                event_id, artifact_index, artifact_digest
            ) VALUES (?1, ?2, ?3)
            "#,
            params![event_id, index as i64, digest],
        )?;
    }
    write_event_revocation_commit(
        transaction,
        event_id,
        admission.last_observed_revocation.as_ref(),
    )?;
    for ((quota, before), after) in quotas.iter().zip(quota_before).zip(quota_after) {
        transaction.execute(
            r#"
            INSERT INTO budget_event_quota_members (
                event_id, profile, owner_id, grant_index, max_invocations,
                reserved_before, captured_before, reserved_after, captured_after
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                event_id,
                quota.key.profile.as_str(),
                &quota.key.owner_id,
                quota_index(&quota.key)?,
                i64::from(quota.max_invocations),
                i64::from(before.reserved),
                i64::from(before.captured),
                i64::from(after.reserved),
                i64::from(after.captured),
            ],
        )?;
    }
    if let (Some(cumulative), Some(state), Some(before), Some(after)) = (
        cumulative,
        cumulative_state,
        cumulative_before,
        cumulative_after,
    ) {
        transaction.execute(
            r#"
            INSERT INTO budget_event_cumulative_approval (
                event_id, operation_id, authority_id, owner_id,
                approval_budget_id, approval_budget_epoch, root_grant_hash,
                delegation_root_id, root_binding_digest, currency,
                authority_threshold_units, effective_threshold_units,
                requested_authorized_units, state_before, state_after,
                reserved_authorized_before, captured_authorized_before,
                reserved_authorized_after, captured_authorized_after,
                version_before, version_after
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                ?11, ?12, ?13, NULL, ?14, ?15, ?16, ?17, ?18, ?19, ?20
            )
            "#,
            params![
                event_id,
                &cumulative.operation_id,
                &cumulative.account_key.authority_id,
                &cumulative.account_key.owner_id,
                &cumulative.account_key.approval_budget_id,
                budget_u64_to_sqlite(
                    cumulative.account_key.approval_budget_epoch,
                    "approval_budget_epoch",
                )?,
                &cumulative.account_key.root_grant_hash,
                cumulative.account_key.delegation_root_id.as_deref(),
                cumulative.account_key.root_binding_digest.as_deref(),
                &cumulative.account_key.currency,
                budget_u64_to_sqlite(
                    cumulative.authority_threshold.units,
                    "authority_threshold_units",
                )?,
                budget_u64_to_sqlite(
                    cumulative.effective_threshold.units,
                    "effective_threshold_units",
                )?,
                budget_u64_to_sqlite(
                    cumulative.requested_authorized.units,
                    "requested_authorized_units",
                )?,
                cumulative_state_text(state),
                budget_u64_to_sqlite(before.reserved, "reserved_authorized_before")?,
                budget_u64_to_sqlite(before.captured, "captured_authorized_before")?,
                budget_u64_to_sqlite(after.reserved, "reserved_authorized_after")?,
                budget_u64_to_sqlite(after.captured, "captured_authorized_after")?,
                budget_u64_to_sqlite(before.version, "version_before")?,
                budget_u64_to_sqlite(after.version, "version_after")?,
            ],
        )?;
    } else if let (Some(cumulative), Some(state), Some(before)) =
        (cumulative, cumulative_state, cumulative_before)
    {
        transaction.execute(
            r#"
            INSERT INTO budget_event_cumulative_approval (
                event_id, operation_id, authority_id, owner_id,
                approval_budget_id, approval_budget_epoch, root_grant_hash,
                delegation_root_id, root_binding_digest, currency,
                authority_threshold_units, effective_threshold_units,
                requested_authorized_units, state_before, state_after,
                reserved_authorized_before, captured_authorized_before,
                reserved_authorized_after, captured_authorized_after,
                version_before, version_after
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                ?11, ?12, ?13, NULL, ?14, ?15, ?16, ?15, ?16, ?17, ?17
            )
            "#,
            params![
                event_id,
                &cumulative.operation_id,
                &cumulative.account_key.authority_id,
                &cumulative.account_key.owner_id,
                &cumulative.account_key.approval_budget_id,
                budget_u64_to_sqlite(
                    cumulative.account_key.approval_budget_epoch,
                    "approval_budget_epoch",
                )?,
                &cumulative.account_key.root_grant_hash,
                cumulative.account_key.delegation_root_id.as_deref(),
                cumulative.account_key.root_binding_digest.as_deref(),
                &cumulative.account_key.currency,
                budget_u64_to_sqlite(
                    cumulative.authority_threshold.units,
                    "authority_threshold_units",
                )?,
                budget_u64_to_sqlite(
                    cumulative.effective_threshold.units,
                    "effective_threshold_units",
                )?,
                budget_u64_to_sqlite(
                    cumulative.requested_authorized.units,
                    "requested_authorized_units",
                )?,
                cumulative_state_text(state),
                budget_u64_to_sqlite(before.reserved, "reserved_authorized_before")?,
                budget_u64_to_sqlite(before.captured, "captured_authorized_before")?,
                budget_u64_to_sqlite(before.version, "version_before")?,
            ],
        )?;
    }
    Ok(())
}

fn load_strings(
    transaction: &Transaction<'_>,
    sql: &str,
    id: &str,
) -> Result<Vec<String>, BudgetStoreError> {
    let mut statement = transaction.prepare(sql)?;
    let values = statement
        .query_map(params![id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into);
    values
}

pub(super) struct ProjectionContract {
    pub(super) operation_id: String,
    pub(super) revocation_set_digest: String,
    pub(super) expected_revocation_count: usize,
    pub(super) expected_quota_count: usize,
    pub(super) expected_artifact_count: usize,
    pub(super) has_cumulative_approval: bool,
    pub(super) has_revocation_commit: bool,
}

type ProjectionContractRow = (
    String,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<bool>,
    Option<bool>,
    Option<i64>,
);

fn projection_contract(
    row: ProjectionContractRow,
    identity: &str,
) -> Result<ProjectionContract, BudgetStoreError> {
    if row.0 != "composite_v1" {
        return Err(BudgetStoreError::Invariant(format!(
            "budget projection `{identity}` is not marked composite_v1"
        )));
    }
    Ok(ProjectionContract {
        operation_id: row.1.filter(|value| !value.is_empty()).ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "composite budget projection `{identity}` lost operation_id"
            ))
        })?,
        revocation_set_digest: row.2.ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "composite budget projection `{identity}` lost revocation digest"
            ))
        })?,
        expected_revocation_count: usize::try_from(row.7.ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "composite budget projection `{identity}` lost revocation count"
            ))
        })?)
        .map_err(|_| BudgetStoreError::Invariant("negative revocation count".to_string()))?,
        expected_quota_count: usize::try_from(row.3.ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "composite budget projection `{identity}` lost quota count"
            ))
        })?)
        .map_err(|_| BudgetStoreError::Invariant("negative quota count".to_string()))?,
        expected_artifact_count: usize::try_from(row.4.ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "composite budget projection `{identity}` lost artifact count"
            ))
        })?)
        .map_err(|_| BudgetStoreError::Invariant("negative artifact count".to_string()))?,
        has_cumulative_approval: row.5.ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "composite budget projection `{identity}` lost cumulative flag"
            ))
        })?,
        has_revocation_commit: row.6.ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "composite budget projection `{identity}` lost revocation commit flag"
            ))
        })?,
    })
}

pub(super) fn load_event_projection_contract(
    transaction: &Transaction<'_>,
    event_id: &str,
) -> Result<ProjectionContract, BudgetStoreError> {
    let row = transaction.query_row(
        r#"
        SELECT projection_kind, operation_id, revocation_set_digest,
               expected_quota_count, expected_artifact_count,
               has_cumulative_approval, has_revocation_commit,
               expected_revocation_count
        FROM budget_mutation_events WHERE event_id = ?1
        "#,
        params![event_id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            ))
        },
    )?;
    projection_contract(row, event_id)
}

fn load_hold_projection_contract(
    transaction: &Transaction<'_>,
    hold_id: &str,
) -> Result<ProjectionContract, BudgetStoreError> {
    let row = transaction.query_row(
        r#"
        SELECT projection_kind, operation_id, revocation_set_digest,
               expected_quota_count, expected_artifact_count,
               has_cumulative_approval, has_revocation_commit,
               expected_revocation_count
        FROM budget_authorization_holds WHERE hold_id = ?1
        "#,
        params![hold_id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            ))
        },
    )?;
    projection_contract(row, hold_id)
}

pub(super) fn require_expected_count(
    identity: &str,
    projection: &str,
    expected: usize,
    actual: usize,
) -> Result<(), BudgetStoreError> {
    if expected != actual {
        return Err(BudgetStoreError::Invariant(format!(
            "composite budget projection `{identity}` expected {expected} {projection} rows, found {actual}"
        )));
    }
    Ok(())
}

pub(super) fn load_authorization_request(
    transaction: &Transaction<'_>,
    event: &BudgetMutationRecord,
) -> Result<BudgetAuthorizeHoldRequest, BudgetStoreError> {
    if !matches!(
        event.kind,
        BudgetMutationKind::ReserveInvocation | BudgetMutationKind::AuthorizeExposure
    ) {
        return Err(BudgetStoreError::Invariant(
            "budget event is not a composite authorization".to_string(),
        ));
    }
    let contract = load_event_projection_contract(transaction, &event.event_id)?;
    let row = transaction.query_row(
        r#"
        SELECT supplemental_verifier_id, supplemental_verifier_config_digest,
               supplemental_artifact_digest, supplemental_expires_at,
               invocation_quotas_explicit
        FROM budget_mutation_events WHERE event_id = ?1
        "#,
        params![&event.event_id],
        |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<bool>>(4)?,
            ))
        },
    )?;
    let revocation_ids = load_strings(
        transaction,
        r#"
        SELECT capability_id FROM budget_event_revocation_members
        WHERE event_id = ?1 ORDER BY member_index
        "#,
        &event.event_id,
    )?;
    require_expected_count(
        &event.event_id,
        "revocation",
        contract.expected_revocation_count,
        revocation_ids.len(),
    )?;
    let revocation_set = CanonicalRevocationSet::from_canonical_parts(
        revocation_ids,
        contract.revocation_set_digest,
    )
    .map_err(|error| {
        BudgetStoreError::Invariant(format!("stored revocation set is invalid: {error}"))
    })?;
    let authorization_artifact_digests = load_strings(
        transaction,
        r#"
        SELECT artifact_digest FROM budget_event_authorization_artifacts
        WHERE event_id = ?1 ORDER BY artifact_index
        "#,
        &event.event_id,
    )?;
    require_expected_count(
        &event.event_id,
        "authorization artifact",
        contract.expected_artifact_count,
        authorization_artifact_digests.len(),
    )?;
    let all_quotas = load_event_quotas(transaction, &event.event_id)?;
    require_expected_count(
        &event.event_id,
        "quota",
        contract.expected_quota_count,
        all_quotas.len(),
    )?;
    let invocation_quotas = if row.4.unwrap_or(false) {
        all_quotas.clone()
    } else {
        Vec::new()
    };
    let request = BudgetAuthorizeHoldRequest {
        capability_id: event.capability_id.clone(),
        grant_index: usize::try_from(event.grant_index).map_err(|_| {
            BudgetStoreError::Invariant("event grant_index does not fit usize".to_string())
        })?,
        max_invocations: event.max_invocations,
        invocation_quotas,
        cumulative_approval: {
            let cumulative = load_event_cumulative_request(transaction, &event.event_id)?;
            if contract.has_cumulative_approval != cumulative.is_some() {
                return Err(BudgetStoreError::Invariant(format!(
                    "composite budget event `{}` lost cumulative approval projection",
                    event.event_id
                )));
            }
            cumulative
        },
        admission_binding: Some(BudgetAdmissionBinding {
            operation_id: contract.operation_id,
            revocation_set,
            authorization_artifact_digests,
            last_observed_revocation: {
                let commit = load_event_revocation_commit(transaction, &event.event_id)?;
                if contract.has_revocation_commit != commit.is_some() {
                    return Err(BudgetStoreError::Invariant(format!(
                        "composite budget event `{}` lost revocation commit projection",
                        event.event_id
                    )));
                }
                commit
            },
            supplemental_verifier_id: row.0,
            supplemental_verifier_config_digest: row.1,
            supplemental_authorization_artifact_digest: row.2,
            supplemental_authorization_expires_at: row
                .3
                .map(|value| {
                    u64::try_from(value).map_err(|_| {
                        BudgetStoreError::Invariant("negative supplemental expiration".to_string())
                    })
                })
                .transpose()?,
        }),
        requested_exposure_units: event.exposure_units,
        max_cost_per_invocation: event.max_cost_per_invocation,
        max_total_cost_units: event.max_total_cost_units,
        hold_id: event.hold_id.clone(),
        event_id: Some(event.event_id.clone()),
        authority: event.authority.clone(),
    };
    validate_stored_composite_binding(
        &request.capability_id,
        request.grant_index,
        request.hold_id.as_deref().unwrap_or(""),
        request.event_id.as_deref().unwrap_or(""),
        request.admission_binding.as_ref().ok_or_else(|| {
            BudgetStoreError::Invariant("stored authorization lost admission binding".to_string())
        })?,
        &all_quotas,
        request.cumulative_approval.as_ref(),
    )?;
    request.validate()?;
    Ok(request)
}

fn load_event_quotas(
    transaction: &Transaction<'_>,
    event_id: &str,
) -> Result<Vec<BudgetInvocationQuota>, BudgetStoreError> {
    let mut statement = transaction.prepare(
        r#"
        SELECT profile, owner_id, grant_index, max_invocations
        FROM budget_event_quota_members
        WHERE event_id = ?1
        ORDER BY CASE profile
            WHEN 'chio.grant-invocation.v1' THEN 0
            WHEN 'chio.aggregate-capability-invocation.v1' THEN 1
            WHEN 'chio.aggregate-family-invocation.v1' THEN 2
            WHEN 'chio.broker-capability-execution.v1' THEN 3
            ELSE 99 END,
            owner_id, grant_index
        "#,
    )?;
    let rows = statement.query_map(params![event_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;
    rows.map(|row| {
        let row = row?;
        Ok(BudgetInvocationQuota {
            key: quota_key(&row.0, row.1, row.2)?,
            max_invocations: u32::try_from(row.3).map_err(|_| {
                BudgetStoreError::Invariant("invalid stored quota maximum".to_string())
            })?,
        })
    })
    .collect()
}

pub(super) fn load_event_cumulative_request(
    transaction: &Transaction<'_>,
    event_id: &str,
) -> Result<Option<BudgetCumulativeApprovalRequest>, BudgetStoreError> {
    type Row = (
        String,
        String,
        String,
        String,
        i64,
        String,
        Option<String>,
        Option<String>,
        String,
        i64,
        i64,
        i64,
    );
    let row: Option<Row> = transaction
        .query_row(
            r#"
            SELECT operation_id, authority_id, owner_id, approval_budget_id,
                   approval_budget_epoch, root_grant_hash, delegation_root_id,
                   root_binding_digest, currency, authority_threshold_units,
                   effective_threshold_units, requested_authorized_units
            FROM budget_event_cumulative_approval WHERE event_id = ?1
            "#,
            params![event_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                ))
            },
        )
        .optional()?;
    row.map(|row| {
        let approval_budget_epoch = u64::try_from(row.4).map_err(|_| {
            BudgetStoreError::Invariant("negative approval budget epoch".to_string())
        })?;
        let units = |value: i64, field: &str| {
            u64::try_from(value)
                .map_err(|_| BudgetStoreError::Invariant(format!("negative {field}")))
        };
        let request = BudgetCumulativeApprovalRequest {
            operation_id: row.0,
            account_key: BudgetCumulativeApprovalAccountKey {
                authority_id: row.1,
                owner_id: row.2,
                approval_budget_id: row.3,
                approval_budget_epoch,
                root_grant_hash: row.5,
                delegation_root_id: row.6,
                root_binding_digest: row.7,
                currency: row.8.clone(),
            },
            authority_threshold: MonetaryAmount {
                units: units(row.9, "authority threshold")?,
                currency: row.8.clone(),
            },
            effective_threshold: MonetaryAmount {
                units: units(row.10, "effective threshold")?,
                currency: row.8.clone(),
            },
            requested_authorized: MonetaryAmount {
                units: units(row.11, "requested authorized units")?,
                currency: row.8,
            },
        };
        validate_cumulative_request(&request)?;
        Ok(request)
    })
    .transpose()
}

pub(super) fn cumulative_usage(
    request: &BudgetCumulativeApprovalRequest,
    state: BudgetCumulativeApprovalState,
    account: &CumulativeAccount,
) -> BudgetCumulativeApprovalUsage {
    BudgetCumulativeApprovalUsage {
        operation_id: request.operation_id.clone(),
        account_key: request.account_key.clone(),
        authority_threshold: request.authority_threshold.clone(),
        effective_threshold: request.effective_threshold.clone(),
        requested_authorized: request.requested_authorized.clone(),
        reserved_authorized_after: MonetaryAmount {
            units: account.reserved,
            currency: account.currency.clone(),
        },
        captured_authorized_after: MonetaryAmount {
            units: account.captured,
            currency: account.currency.clone(),
        },
        state,
        version: account.version,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn authorization_decision(
    store: &SqliteBudgetStore,
    request: BudgetAuthorizeHoldRequest,
    outcome: BudgetAuthorizationOutcome,
    event_seq: u64,
    recorded_at: i64,
    usage: BudgetUsageRecord,
    quotas: Vec<QuotaState>,
    cumulative_state: Option<BudgetCumulativeApprovalState>,
    cumulative_account: Option<CumulativeAccount>,
) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
    let quota_usages = quotas.iter().map(QuotaState::usage).collect();
    let cumulative = request
        .cumulative_approval
        .as_ref()
        .zip(cumulative_state)
        .zip(cumulative_account.as_ref())
        .map(|((request, state), account)| cumulative_usage(request, state, account));
    let metadata = BudgetCommitMetadata {
        authority: request.authority.clone(),
        guarantee_level: store.budget_guarantee_level(),
        budget_profile: store.budget_authority_profile(),
        metering_profile: store.budget_metering_profile(),
        budget_commit_index: Some(event_seq),
        event_id: request.event_id.clone(),
        recorded_at_unix_seconds: u64::try_from(recorded_at).ok(),
    };
    let committed_cost_units_after = usage.committed_cost_units()?;
    let monetary_state =
        if outcome == BudgetAuthorizationOutcome::Denied || request.requested_exposure_units == 0 {
            BudgetMonetaryState::None
        } else {
            BudgetMonetaryState::Exposed
        };
    match outcome {
        BudgetAuthorizationOutcome::Denied => {
            Ok(BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                hold_id: request.hold_id,
                admission_binding: request.admission_binding,
                attempted_exposure_units: request.requested_exposure_units,
                committed_cost_units_after,
                invocation_count_after: usage.invocation_count,
                invocation_quota_usages: quota_usages,
                cumulative_approval: None,
                invocation_state: BudgetInvocationState::Denied,
                monetary_state,
                metadata,
            }))
        }
        BudgetAuthorizationOutcome::ApprovalRequired => Ok(
            BudgetAuthorizeHoldDecision::ApprovalRequired(ApprovalRequiredBudgetHold {
                hold_id: request.hold_id.ok_or_else(|| {
                    BudgetStoreError::Invariant("approval-required hold lost hold_id".to_string())
                })?,
                admission_binding: request.admission_binding.ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "approval-required hold lost admission binding".to_string(),
                    )
                })?,
                authorized_exposure_units: request.requested_exposure_units,
                committed_cost_units_after,
                invocation_count_after: usage.invocation_count,
                invocation_quota_usages: quota_usages,
                cumulative_approval: cumulative.ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "approval-required hold lost cumulative projection".to_string(),
                    )
                })?,
                invocation_state: BudgetInvocationState::Authorized,
                monetary_state,
                metadata,
            }),
        ),
        BudgetAuthorizationOutcome::Authorized => Ok(BudgetAuthorizeHoldDecision::Authorized(
            AuthorizedBudgetHold {
                hold_id: request.hold_id,
                admission_binding: request.admission_binding,
                authorized_exposure_units: request.requested_exposure_units,
                committed_cost_units_after,
                invocation_count_after: usage.invocation_count,
                invocation_quota_usages: quota_usages,
                cumulative_approval: cumulative,
                invocation_state: BudgetInvocationState::Authorized,
                monetary_state,
                metadata,
            },
        )),
    }
}

pub(super) fn decision_from_persisted_event(
    store: &SqliteBudgetStore,
    transaction: &Transaction<'_>,
    event: &BudgetMutationRecord,
) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
    let request = load_authorization_request(transaction, event)?;
    let outcome_text: String = transaction.query_row(
        "SELECT authorization_outcome FROM budget_mutation_events WHERE event_id = ?1",
        params![&event.event_id],
        |row| row.get(0),
    )?;
    let outcome = budget_authorization_outcome(&outcome_text)?;
    let quota_states = load_event_quota_after(transaction, &event.event_id)?;
    let cumulative_state = load_event_cumulative_state(transaction, &event.event_id)?;
    let cumulative_account = load_event_cumulative_after(transaction, &event.event_id)?;
    authorization_decision(
        store,
        request,
        outcome,
        event.event_seq,
        event.recorded_at,
        BudgetUsageRecord {
            capability_id: event.capability_id.clone(),
            grant_index: event.grant_index,
            invocation_count: event.invocation_count_after,
            updated_at: event.recorded_at,
            seq: event.usage_seq.unwrap_or(0),
            total_cost_exposed: event.total_cost_exposed_after,
            total_cost_realized_spend: event.total_cost_realized_spend_after,
        },
        quota_states,
        cumulative_state,
        cumulative_account,
    )
}

pub(super) fn load_event_quota_after(
    transaction: &Transaction<'_>,
    event_id: &str,
) -> Result<Vec<QuotaState>, BudgetStoreError> {
    let mut statement = transaction.prepare(
        r#"
        SELECT profile, owner_id, grant_index, max_invocations,
               reserved_after, captured_after
        FROM budget_event_quota_members
        WHERE event_id = ?1
        ORDER BY CASE profile
            WHEN 'chio.grant-invocation.v1' THEN 0
            WHEN 'chio.aggregate-capability-invocation.v1' THEN 1
            WHEN 'chio.aggregate-family-invocation.v1' THEN 2
            WHEN 'chio.broker-capability-execution.v1' THEN 3
            ELSE 99 END,
            owner_id, grant_index
        "#,
    )?;
    let rows = statement.query_map(params![event_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, i64>(5)?,
        ))
    })?;
    rows.map(|row| {
        let row = row?;
        let maximum = u32::try_from(row.3)
            .map_err(|_| BudgetStoreError::Invariant("invalid quota maximum".to_string()))?;
        let quota = BudgetInvocationQuota {
            key: quota_key(&row.0, row.1, row.2)?,
            max_invocations: maximum,
        };
        Ok(QuotaState {
            quota,
            maximum,
            reserved: u32::try_from(row.4).map_err(|_| {
                BudgetStoreError::Invariant("invalid reserved quota count".to_string())
            })?,
            captured: u32::try_from(row.5).map_err(|_| {
                BudgetStoreError::Invariant("invalid captured quota count".to_string())
            })?,
            version: 0,
        })
    })
    .collect()
}

pub(super) fn load_event_cumulative_state(
    transaction: &Transaction<'_>,
    event_id: &str,
) -> Result<Option<BudgetCumulativeApprovalState>, BudgetStoreError> {
    transaction
        .query_row(
            "SELECT state_after FROM budget_event_cumulative_approval WHERE event_id = ?1",
            params![event_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|value| cumulative_state(&value))
        .transpose()
}

pub(super) fn load_event_cumulative_after(
    transaction: &Transaction<'_>,
    event_id: &str,
) -> Result<Option<CumulativeAccount>, BudgetStoreError> {
    let Some(request) = load_event_cumulative_request(transaction, event_id)? else {
        return Ok(None);
    };
    transaction
        .query_row(
            r#"
            SELECT reserved_authorized_after, captured_authorized_after, version_after
            FROM budget_event_cumulative_approval WHERE event_id = ?1
            "#,
            params![event_id],
            |row| {
                Ok((
                    budget_u64_from_row(row, 0, "reserved_authorized_after")?,
                    budget_u64_from_row(row, 1, "captured_authorized_after")?,
                    budget_u64_from_row(row, 2, "version_after")?,
                ))
            },
        )
        .optional()?
        .map(|row| {
            Ok(CumulativeAccount {
                key: request.account_key.clone(),
                root_grant_hash: request.account_key.root_grant_hash.clone(),
                delegation_root_id: request.account_key.delegation_root_id.clone(),
                root_binding_digest: request.account_key.root_binding_digest.clone(),
                currency: request.account_key.currency.clone(),
                authority_threshold: request.authority_threshold.units,
                reserved: row.0,
                captured: row.1,
                version: row.2,
            })
        })
        .transpose()
}

pub(super) fn latest_hold_event_seq(
    transaction: &Transaction<'_>,
    hold_id: &str,
) -> Result<Option<u64>, BudgetStoreError> {
    transaction
        .query_row(
            "SELECT MAX(event_seq) FROM budget_mutation_events WHERE hold_id = ?1",
            params![hold_id],
            |row| row.get::<_, Option<i64>>(0),
        )?
        .map(|value| {
            u64::try_from(value).map_err(|_| {
                BudgetStoreError::Invariant("negative budget event sequence".to_string())
            })
        })
        .transpose()
}

pub(super) fn load_structured_hold(
    transaction: &Transaction<'_>,
    hold_id: &str,
) -> Result<Option<StructuredHold>, BudgetStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT capability_id, grant_index, authorized_exposure_units,
                   remaining_exposure_units, invocation_state, monetary_state,
                   projection_kind, supplemental_verifier_id,
                   supplemental_verifier_config_digest, supplemental_artifact_digest,
                   supplemental_expires_at, authority_id, lease_id, lease_epoch
            FROM budget_authorization_holds WHERE hold_id = ?1
            "#,
            params![hold_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    budget_u64_from_row(row, 2, "authorized_exposure_units")?,
                    budget_u64_from_row(row, 3, "remaining_exposure_units")?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    optional_budget_u64_from_row(row, 10, "supplemental_expires_at")?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<i64>>(13)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.6 != "composite_v1" {
        return Ok(None);
    }
    let contract = load_hold_projection_contract(transaction, hold_id)?;
    let revocation_ids = load_strings(
        transaction,
        r#"
        SELECT capability_id FROM budget_hold_revocation_members
        WHERE hold_id = ?1 ORDER BY member_index
        "#,
        hold_id,
    )?;
    require_expected_count(
        hold_id,
        "revocation",
        contract.expected_revocation_count,
        revocation_ids.len(),
    )?;
    let revocation_set = CanonicalRevocationSet::from_canonical_parts(
        revocation_ids,
        contract.revocation_set_digest,
    )
    .map_err(|error| {
        BudgetStoreError::Invariant(format!("stored revocation set is invalid: {error}"))
    })?;
    let authorization_artifact_digests = load_strings(
        transaction,
        r#"
        SELECT artifact_digest FROM budget_hold_authorization_artifacts
        WHERE hold_id = ?1 ORDER BY artifact_index
        "#,
        hold_id,
    )?;
    require_expected_count(
        hold_id,
        "authorization artifact",
        contract.expected_artifact_count,
        authorization_artifact_digests.len(),
    )?;
    let revocation_commit = load_hold_revocation_commit(transaction, hold_id)?;
    if contract.has_revocation_commit != revocation_commit.is_some() {
        return Err(BudgetStoreError::Invariant(format!(
            "composite budget hold `{hold_id}` lost revocation commit projection"
        )));
    }
    let quotas = load_hold_quotas(transaction, hold_id)?;
    require_expected_count(
        hold_id,
        "quota",
        contract.expected_quota_count,
        quotas.len(),
    )?;
    let cumulative = load_hold_cumulative(transaction, hold_id)?;
    if contract.has_cumulative_approval != cumulative.is_some() {
        return Err(BudgetStoreError::Invariant(format!(
            "composite budget hold `{hold_id}` lost cumulative approval projection"
        )));
    }
    let admission = BudgetAdmissionBinding {
        operation_id: contract.operation_id,
        revocation_set,
        authorization_artifact_digests,
        last_observed_revocation: revocation_commit,
        supplemental_verifier_id: row.7,
        supplemental_verifier_config_digest: row.8,
        supplemental_authorization_artifact_digest: row.9,
        supplemental_authorization_expires_at: row.10,
    };
    validate_stored_composite_binding(
        &row.0,
        usize::try_from(row.1)
            .map_err(|_| BudgetStoreError::Invariant("invalid hold grant_index".to_string()))?,
        hold_id,
        hold_id,
        &admission,
        &quotas,
        cumulative.as_ref().map(|value| &value.0),
    )?;
    let authority = sqlite_budget_event_authority(row.11, row.12, row.13)?;
    let persisted_authority = authority.as_ref().ok_or_else(|| {
        BudgetStoreError::Invariant(format!(
            "composite budget hold `{hold_id}` lost serving authority"
        ))
    })?;
    crate::serving_owner::verify_historical_budget_authority(transaction, persisted_authority)?;
    Ok(Some(StructuredHold {
        hold_id: hold_id.to_string(),
        capability_id: row.0,
        grant_index: usize::try_from(row.1)
            .map_err(|_| BudgetStoreError::Invariant("invalid hold grant_index".to_string()))?,
        admission,
        invocation_state: budget_invocation_state(row.4.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "composite budget hold `{hold_id}` lost invocation state"
            ))
        })?)?,
        monetary_state: budget_monetary_state(row.5.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "composite budget hold `{hold_id}` lost monetary state"
            ))
        })?)?,
        authorized_exposure: row.2,
        remaining_exposure: row.3,
        authority,
        quotas,
        cumulative,
    }))
}

fn load_hold_quotas(
    transaction: &Transaction<'_>,
    hold_id: &str,
) -> Result<Vec<BudgetInvocationQuota>, BudgetStoreError> {
    let mut statement = transaction.prepare(
        r#"
        SELECT profile, owner_id, grant_index, max_invocations
        FROM budget_hold_quota_members WHERE hold_id = ?1
        ORDER BY CASE profile
            WHEN 'chio.grant-invocation.v1' THEN 0
            WHEN 'chio.aggregate-capability-invocation.v1' THEN 1
            WHEN 'chio.aggregate-family-invocation.v1' THEN 2
            WHEN 'chio.broker-capability-execution.v1' THEN 3
            ELSE 99 END,
            owner_id, grant_index
        "#,
    )?;
    let rows = statement.query_map(params![hold_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;
    rows.map(|row| {
        let row = row?;
        Ok(BudgetInvocationQuota {
            key: quota_key(&row.0, row.1, row.2)?,
            max_invocations: u32::try_from(row.3).map_err(|_| {
                BudgetStoreError::Invariant("invalid hold quota maximum".to_string())
            })?,
        })
    })
    .collect()
}
