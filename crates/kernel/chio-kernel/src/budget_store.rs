use chio_log_redact::redacted;

#[derive(Debug, thiserror::Error)]
pub enum BudgetStoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("failed to prepare budget store directory: {0}")]
    Io(#[from] std::io::Error),

    #[error("budget arithmetic overflow: {0}")]
    Overflow(String),

    #[error("budget state invariant violated: {0}")]
    Invariant(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetUsageRecord {
    pub capability_id: String,
    pub grant_index: u32,
    pub invocation_count: u32,
    pub updated_at: i64,
    pub seq: u64,
    pub total_cost_exposed: u64,
    pub total_cost_realized_spend: u64,
}

impl BudgetUsageRecord {
    pub fn committed_cost_units(&self) -> Result<u64, BudgetStoreError> {
        checked_committed_cost_units(self.total_cost_exposed, self.total_cost_realized_spend)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetMutationKind {
    IncrementInvocation,
    AuthorizeExposure,
    ReverseExposure,
    ReleaseExposure,
    ReconcileSpend,
    ExpireHold,
}

impl BudgetMutationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IncrementInvocation => "increment_invocation",
            Self::AuthorizeExposure => "authorize_exposure",
            Self::ReverseExposure => "reverse_exposure",
            Self::ReleaseExposure => "release_exposure",
            Self::ReconcileSpend => "reconcile_spend",
            Self::ExpireHold => "expire_hold",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "increment_invocation" => Some(Self::IncrementInvocation),
            "authorize_exposure" => Some(Self::AuthorizeExposure),
            "reverse_exposure" => Some(Self::ReverseExposure),
            "release_exposure" => Some(Self::ReleaseExposure),
            "reconcile_spend" => Some(Self::ReconcileSpend),
            "expire_hold" => Some(Self::ExpireHold),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetEventAuthority {
    pub authority_id: String,
    pub lease_id: String,
    pub lease_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetMutationRecord {
    pub event_id: String,
    pub hold_id: Option<String>,
    pub capability_id: String,
    pub grant_index: u32,
    pub kind: BudgetMutationKind,
    pub allowed: Option<bool>,
    pub recorded_at: i64,
    pub event_seq: u64,
    pub usage_seq: Option<u64>,
    pub exposure_units: u64,
    pub realized_spend_units: u64,
    pub max_invocations: Option<u32>,
    pub max_cost_per_invocation: Option<u64>,
    pub max_total_cost_units: Option<u64>,
    pub invocation_count_after: u32,
    pub total_cost_exposed_after: u64,
    pub total_cost_realized_spend_after: u64,
    pub authority: Option<BudgetEventAuthority>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetGuaranteeLevel {
    SingleNodeAtomic,
    HaLinearizable,
    PartitionEscrowed,
    AdvisoryPosthoc,
}

impl BudgetGuaranteeLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingleNodeAtomic => "single_node_atomic",
            Self::HaLinearizable => "ha_linearizable",
            Self::PartitionEscrowed => "partition_escrowed",
            Self::AdvisoryPosthoc => "advisory_posthoc",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetAuthorityProfile {
    AuthoritativeHoldEvent,
}

impl BudgetAuthorityProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthoritativeHoldEvent => "authoritative_hold_event",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetMeteringProfile {
    MaxCostPreauthorizeThenReconcileActual,
}

impl BudgetMeteringProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MaxCostPreauthorizeThenReconcileActual => {
                "max_cost_preauthorize_then_reconcile_actual"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetCommitMetadata {
    pub authority: Option<BudgetEventAuthority>,
    pub guarantee_level: BudgetGuaranteeLevel,
    pub budget_profile: BudgetAuthorityProfile,
    pub metering_profile: BudgetMeteringProfile,
    pub budget_commit_index: Option<u64>,
    pub event_id: Option<String>,
}

impl BudgetCommitMetadata {
    pub fn budget_term(&self) -> Option<String> {
        self.authority
            .as_ref()
            .map(|authority| format!("{}:{}", authority.authority_id, authority.lease_epoch))
    }
}

/// Assemble the commit metadata a hold decision carries, stamped with the
/// store's guarantee and metering profiles. Public so store implementations
/// that override the defaulted hold methods can produce identical metadata.
pub fn budget_commit_metadata<T: BudgetStore + ?Sized>(
    store: &T,
    authority: Option<BudgetEventAuthority>,
    budget_commit_index: Option<u64>,
    event_id: Option<String>,
) -> BudgetCommitMetadata {
    BudgetCommitMetadata {
        authority,
        guarantee_level: store.budget_guarantee_level(),
        budget_profile: store.budget_authority_profile(),
        metering_profile: store.budget_metering_profile(),
        budget_commit_index,
        event_id,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetAuthorizeHoldRequest {
    pub capability_id: String,
    pub grant_index: usize,
    pub max_invocations: Option<u32>,
    pub requested_exposure_units: u64,
    pub max_cost_per_invocation: Option<u64>,
    pub max_total_cost_units: Option<u64>,
    pub hold_id: Option<String>,
    pub event_id: Option<String>,
    pub authority: Option<BudgetEventAuthority>,
    /// Optional payment-journal row committed in the SAME transaction as
    /// the hold write, so the money path's recoverable record is durable
    /// before the rail is touched. `None` for non-monetary calls and for
    /// stores without the journal.
    pub payment_journal: Option<crate::payment::PaymentJournalRecord>,
}

/// Read model of an open budget hold, for the orphaned-hold sweeper and the
/// operator CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenHoldSummary {
    pub hold_id: String,
    pub capability_id: String,
    pub grant_index: u32,
    pub remaining_exposure_units: u64,
    pub created_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetReleaseHoldRequest {
    pub capability_id: String,
    pub grant_index: usize,
    pub released_exposure_units: u64,
    pub hold_id: Option<String>,
    pub event_id: Option<String>,
    pub authority: Option<BudgetEventAuthority>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetReverseHoldRequest {
    pub capability_id: String,
    pub grant_index: usize,
    pub reversed_exposure_units: u64,
    pub hold_id: Option<String>,
    pub event_id: Option<String>,
    pub authority: Option<BudgetEventAuthority>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetReconcileHoldRequest {
    pub capability_id: String,
    pub grant_index: usize,
    pub exposed_cost_units: u64,
    pub realized_spend_units: u64,
    pub hold_id: Option<String>,
    pub event_id: Option<String>,
    pub authority: Option<BudgetEventAuthority>,
}

pub type BudgetCaptureHoldRequest = BudgetReconcileHoldRequest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedBudgetHold {
    pub hold_id: Option<String>,
    pub authorized_exposure_units: u64,
    pub committed_cost_units_after: u64,
    pub invocation_count_after: u32,
    pub metadata: BudgetCommitMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeniedBudgetHold {
    pub hold_id: Option<String>,
    pub attempted_exposure_units: u64,
    pub committed_cost_units_after: u64,
    pub invocation_count_after: u32,
    pub metadata: BudgetCommitMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetAuthorizeHoldDecision {
    Authorized(AuthorizedBudgetHold),
    Denied(DeniedBudgetHold),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetHoldMutationDecision {
    pub hold_id: Option<String>,
    pub exposure_units: u64,
    pub realized_spend_units: u64,
    pub committed_cost_units_after: u64,
    pub invocation_count_after: u32,
    pub metadata: BudgetCommitMetadata,
}

pub type BudgetReleaseHoldDecision = BudgetHoldMutationDecision;
pub type BudgetReverseHoldDecision = BudgetHoldMutationDecision;
pub type BudgetReconcileHoldDecision = BudgetHoldMutationDecision;
pub type BudgetCaptureHoldDecision = BudgetHoldMutationDecision;

pub trait BudgetStore: Send + Sync {
    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError>;

    /// Atomically check monetary budget limits and record provisional exposure if within bounds.
    ///
    /// Checks:
    /// 1. `invocation_count < max_invocations` (if set)
    /// 2. `cost_units <= max_cost_per_invocation` (if set)
    /// 3. `(total_cost_exposed + total_cost_realized_spend + cost_units)
    ///    <= max_total_cost_units` (if set)
    ///
    /// On pass: increments `invocation_count` by 1 and `total_cost_exposed` by
    /// `cost_units`, allocates a new replication seq, returns `Ok(true)`.
    /// On any limit exceeded: rolls back, returns `Ok(false)`.
    ///
    // SAFETY: HA overrun bound = max_cost_per_invocation x node_count
    // In a split-brain scenario, each HA node may independently approve up to
    // one invocation at the full per-invocation cap before the LWW merge
    // propagates the updated total. The maximum possible overrun is therefore
    // bounded by max_cost_per_invocation multiplied by the number of active
    // nodes in the HA cluster.
    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError>;

    #[allow(clippy::too_many_arguments)]
    fn try_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        let _ = hold_id;
        let _ = event_id;
        self.try_charge_cost(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<bool, BudgetStoreError> {
        let _ = authority;
        self.try_charge_cost_with_ids(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
        )
    }

    /// Reverse a previously applied provisional exposure for a pre-execution denial path.
    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError>;

    fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        let _ = hold_id;
        let _ = event_id;
        self.reverse_charge_cost(capability_id, grant_index, cost_units)
    }

    fn reverse_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let _ = authority;
        self.reverse_charge_cost_with_ids(capability_id, grant_index, cost_units, hold_id, event_id)
    }

    /// Release a previously exposed monetary amount without changing invocation count.
    ///
    /// This is used when the kernel needs to release provisional exposure without
    /// realizing any spend in the budget store itself.
    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError>;

    fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        let _ = hold_id;
        let _ = event_id;
        self.reduce_charge_cost(capability_id, grant_index, cost_units)
    }

    fn reduce_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let _ = authority;
        self.reduce_charge_cost_with_ids(capability_id, grant_index, cost_units, hold_id, event_id)
    }

    /// Atomically release provisional exposure and record realized spend.
    ///
    /// This removes `exposed_cost_units` from `total_cost_exposed` and adds
    /// `realized_cost_units` to `total_cost_realized_spend` without changing
    /// invocation count. `realized_cost_units` must not exceed
    /// `exposed_cost_units`.
    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError>;

    fn settle_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        let _ = hold_id;
        let _ = event_id;
        self.settle_charge_cost(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn settle_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let _ = authority;
        self.settle_charge_cost_with_ids(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            hold_id,
            event_id,
        )
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError>;

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError>;

    fn list_mutation_events(
        &self,
        _limit: usize,
        _capability_id: Option<&str>,
        _grant_index: Option<usize>,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "budget mutation events unavailable for this backend".to_string(),
        ))
    }

    fn budget_guarantee_level(&self) -> BudgetGuaranteeLevel {
        BudgetGuaranteeLevel::SingleNodeAtomic
    }

    fn budget_authority_profile(&self) -> BudgetAuthorityProfile {
        BudgetAuthorityProfile::AuthoritativeHoldEvent
    }

    fn budget_metering_profile(&self) -> BudgetMeteringProfile {
        BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual
    }

    /// Open holds created at or before `older_than_unix_ms`, oldest first.
    /// Default: empty (stores without hold rows have nothing to sweep).
    fn list_open_holds_older_than(
        &self,
        _older_than_unix_ms: u64,
        _limit: usize,
    ) -> Result<Vec<OpenHoldSummary>, BudgetStoreError> {
        Ok(Vec::new())
    }

    /// Release the remaining exposure of an open hold, mark it expired, and
    /// append an expire event. Idempotent: a non-open hold returns
    /// `Ok(false)`. Default: unsupported.
    fn expire_open_hold(&self, _hold_id: &str) -> Result<bool, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "open-hold sweep is not supported by this budget store".to_string(),
        ))
    }

    /// Count of holds currently open, for the open-holds gauge. Default: 0.
    fn open_hold_count(&self) -> Result<u64, BudgetStoreError> {
        Ok(0)
    }

    /// Insert a fresh payment-journal row in `HoldPlaced`. Fails closed on
    /// a reused request id. Default: unsupported.
    fn record_payment_journal(
        &self,
        _entry: &crate::payment::PaymentJournalRecord,
    ) -> Result<(), BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "payment journal is not supported by this budget store".to_string(),
        ))
    }

    /// Compare-and-set state advance. `expected` must match the current row
    /// state or the call fails closed. When advancing to `Settling` the
    /// caller MUST pass `settle` so the store stamps the committed action
    /// and amount atomically with the state change; `settle` is invalid on
    /// every other transition. Default: unsupported.
    fn advance_payment_journal(
        &self,
        _request_id: &str,
        _expected: crate::payment::PaymentJournalState,
        _next: crate::payment::PaymentJournalState,
        _authorization_id: Option<&str>,
        _transaction_id: Option<&str>,
        _settle: Option<crate::payment::PaymentSettleIntent>,
    ) -> Result<(), BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "payment journal is not supported by this budget store".to_string(),
        ))
    }

    /// Move the row to `Closed`. Idempotent: an already-closed or absent
    /// row returns `Ok(false)`. Default: unsupported.
    fn close_payment_journal(&self, _request_id: &str) -> Result<bool, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "payment journal is not supported by this budget store".to_string(),
        ))
    }

    /// Rows in a non-terminal state created at or before
    /// `older_than_unix_ms`, oldest first, for boot reconciliation.
    /// Default: empty (stores without the journal have no orphans).
    fn list_incomplete_payment_journal(
        &self,
        _older_than_unix_ms: u64,
    ) -> Result<Vec<crate::payment::PaymentJournalRecord>, BudgetStoreError> {
        Ok(Vec::new())
    }

    /// Look up one incomplete payment-journal row by request id. Scoped
    /// identically to [`Self::list_incomplete_payment_journal`]: a closed,
    /// reconcile-failed, or absent row returns `Ok(None)`, never a stale
    /// terminal record. Default: a linear scan over
    /// `list_incomplete_payment_journal`, correct for any store but O(n) in
    /// the number of open rows; a store expecting many concurrent monetary
    /// orphans should override this with a keyed lookup.
    fn get_payment_journal(
        &self,
        request_id: &str,
    ) -> Result<Option<crate::payment::PaymentJournalRecord>, BudgetStoreError> {
        Ok(self
            .list_incomplete_payment_journal(u64::MAX)?
            .into_iter()
            .find(|row| row.request_id == request_id))
    }

    /// Rail recorded on `request_id`'s payment-journal row, if (and only if)
    /// that row is currently `ReconcileFailed`: a durable operator incident
    /// the money-path pass already gave up on. Distinct from
    /// [`Self::get_payment_journal`], which never surfaces a reconcile-
    /// failed row (see its doc) -- the monetary dispatch-intent reconciler
    /// uses this targeted lookup so such a row is promoted into a
    /// dead-letter instead of being reported as a clean resolution, keeping
    /// the incident visible to RFC-0003's health-flipping dead-letter
    /// surface. Default: `Ok(None)`, for stores without the journal or
    /// without this targeted lookup (they report no incidents, matching
    /// `list_incomplete_payment_journal`'s empty default).
    fn payment_journal_reconcile_failed_rail(
        &self,
        _request_id: &str,
    ) -> Result<Option<String>, BudgetStoreError> {
        Ok(None)
    }

    fn authorize_budget_hold(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        let allowed = self.try_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.max_invocations,
            request.requested_exposure_units,
            request.max_cost_per_invocation,
            request.max_total_cost_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        // The recoverable money record exists only for a granted hold: a
        // budget-denied request never touches the rail, so journaling it
        // would leave an incomplete HoldPlaced row for reconciliation to
        // raise as a false monetary incident. Stores that cannot co-commit
        // the two writes persist the journal immediately after the grant; a
        // store that cannot persist it revokes the hold it just granted and
        // fails closed, so the money path never runs without its crash
        // record. A crash between the grant and the journal write leaves an
        // orphaned hold the sweeper expires, returning both its exposure
        // and its invocation slot.
        if allowed {
            if let Some(journal) = request.payment_journal.as_ref() {
                if let Err(error) = self.record_payment_journal(journal) {
                    let rollback_event_id = request
                        .event_id
                        .as_deref()
                        .map(|event_id| format!("{event_id}:journal-rollback"));
                    if let Err(rollback_error) = self.reverse_charge_cost_with_ids_and_authority(
                        &request.capability_id,
                        request.grant_index,
                        request.requested_exposure_units,
                        request.hold_id.as_deref(),
                        rollback_event_id.as_deref(),
                        request.authority.as_ref(),
                    ) {
                        // The hold leaks until the sweeper expires it;
                        // capacity is fail-closed under-spend meanwhile.
                        tracing::warn!(
                            capability_id = %request.capability_id,
                            grant_index = request.grant_index,
                            reason = %redacted!(&rollback_error.to_string()),
                            "budget hold rollback failed after a journal write failure; the \
                             hold sweeper will expire the orphaned hold"
                        );
                    }
                    return Err(error);
                }
            }
        }
        let usage = self.get_usage(&request.capability_id, request.grant_index)?;
        let committed_cost_units_after = usage
            .as_ref()
            .map(BudgetUsageRecord::committed_cost_units)
            .transpose()?
            .unwrap_or(0);
        let invocation_count_after = usage.as_ref().map_or(0, |usage| usage.invocation_count);
        let metadata = budget_commit_metadata(
            self,
            request.authority,
            allowed
                .then(|| usage.as_ref().map(|usage| usage.seq))
                .flatten(),
            request.event_id,
        );

        if allowed {
            Ok(BudgetAuthorizeHoldDecision::Authorized(
                AuthorizedBudgetHold {
                    hold_id: request.hold_id,
                    authorized_exposure_units: request.requested_exposure_units,
                    committed_cost_units_after,
                    invocation_count_after,
                    metadata,
                },
            ))
        } else {
            Ok(BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                hold_id: request.hold_id,
                attempted_exposure_units: request.requested_exposure_units,
                committed_cost_units_after,
                invocation_count_after,
                metadata,
            }))
        }
    }

    fn reverse_budget_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetReverseHoldDecision, BudgetStoreError> {
        self.reverse_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.reversed_exposure_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        let usage = self.get_usage(&request.capability_id, request.grant_index)?;
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.reversed_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after: usage
                .as_ref()
                .map(BudgetUsageRecord::committed_cost_units)
                .transpose()?
                .unwrap_or(0),
            invocation_count_after: usage.as_ref().map_or(0, |usage| usage.invocation_count),
            metadata: budget_commit_metadata(
                self,
                request.authority,
                usage.as_ref().map(|usage| usage.seq),
                request.event_id,
            ),
        })
    }

    fn release_budget_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetReleaseHoldDecision, BudgetStoreError> {
        self.reduce_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.released_exposure_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        let usage = self.get_usage(&request.capability_id, request.grant_index)?;
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.released_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after: usage
                .as_ref()
                .map(BudgetUsageRecord::committed_cost_units)
                .transpose()?
                .unwrap_or(0),
            invocation_count_after: usage.as_ref().map_or(0, |usage| usage.invocation_count),
            metadata: budget_commit_metadata(
                self,
                request.authority,
                usage.as_ref().map(|usage| usage.seq),
                request.event_id,
            ),
        })
    }

    fn reconcile_budget_hold(
        &self,
        request: BudgetReconcileHoldRequest,
    ) -> Result<BudgetReconcileHoldDecision, BudgetStoreError> {
        self.settle_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.exposed_cost_units,
            request.realized_spend_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        let usage = self.get_usage(&request.capability_id, request.grant_index)?;
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.exposed_cost_units,
            realized_spend_units: request.realized_spend_units,
            committed_cost_units_after: usage
                .as_ref()
                .map(BudgetUsageRecord::committed_cost_units)
                .transpose()?
                .unwrap_or(0),
            invocation_count_after: usage.as_ref().map_or(0, |usage| usage.invocation_count),
            metadata: budget_commit_metadata(
                self,
                request.authority,
                usage.as_ref().map(|usage| usage.seq),
                request.event_id,
            ),
        })
    }

    fn capture_budget_hold(
        &self,
        request: BudgetCaptureHoldRequest,
    ) -> Result<BudgetCaptureHoldDecision, BudgetStoreError> {
        self.reconcile_budget_hold(request)
    }
}

fn checked_committed_cost_units(
    total_cost_exposed: u64,
    total_cost_realized_spend: u64,
) -> Result<u64, BudgetStoreError> {
    total_cost_exposed
        .checked_add(total_cost_realized_spend)
        .ok_or_else(|| {
            BudgetStoreError::Overflow(
                "total_cost_exposed + total_cost_realized_spend overflowed u64".to_string(),
            )
        })
}

mod in_memory;

pub use in_memory::InMemoryBudgetStore;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorize_and_reconcile_hold_preserve_authority_metadata() {
        let store = InMemoryBudgetStore::new();
        let authority = BudgetEventAuthority {
            authority_id: "kernel:test-authority".to_string(),
            lease_id: "single-node".to_string(),
            lease_epoch: 0,
        };

        let decision = store
            .authorize_budget_hold(BudgetAuthorizeHoldRequest {
                capability_id: "cap-budget-1".to_string(),
                grant_index: 0,
                max_invocations: Some(4),
                requested_exposure_units: 100,
                max_cost_per_invocation: Some(100),
                max_total_cost_units: Some(1_000),
                hold_id: Some("hold-budget-1".to_string()),
                event_id: Some("hold-budget-1:authorize".to_string()),
                authority: Some(authority.clone()),
                payment_journal: None,
            })
            .unwrap();
        let BudgetAuthorizeHoldDecision::Authorized(authorized) = decision else {
            panic!("budget hold should be authorized");
        };
        assert_eq!(authorized.committed_cost_units_after, 100);
        assert_eq!(
            authorized.metadata.event_id.as_deref(),
            Some("hold-budget-1:authorize")
        );
        assert_eq!(authorized.metadata.budget_commit_index, Some(1));
        assert_eq!(
            authorized.metadata.budget_term().as_deref(),
            Some("kernel:test-authority:0")
        );

        let reconcile = store
            .reconcile_budget_hold(BudgetReconcileHoldRequest {
                capability_id: "cap-budget-1".to_string(),
                grant_index: 0,
                exposed_cost_units: 100,
                realized_spend_units: 75,
                hold_id: Some("hold-budget-1".to_string()),
                event_id: Some("hold-budget-1:reconcile".to_string()),
                authority: Some(authority.clone()),
            })
            .unwrap();
        assert_eq!(reconcile.committed_cost_units_after, 75);
        assert_eq!(reconcile.realized_spend_units, 75);
        assert_eq!(
            reconcile.metadata.event_id.as_deref(),
            Some("hold-budget-1:reconcile")
        );
        assert_eq!(reconcile.metadata.budget_commit_index, Some(2));
        assert_eq!(reconcile.metadata.authority.as_ref(), Some(&authority));

        let usage = store.get_usage("cap-budget-1", 0).unwrap().unwrap();
        assert_eq!(usage.total_cost_exposed, 0);
        assert_eq!(usage.total_cost_realized_spend, 75);
        assert_eq!(usage.committed_cost_units().unwrap(), 75);

        let events = store
            .list_mutation_events(10, Some("cap-budget-1"), Some(0))
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, BudgetMutationKind::AuthorizeExposure);
        assert_eq!(events[0].authority.as_ref(), Some(&authority));
        assert_eq!(events[1].kind, BudgetMutationKind::ReconcileSpend);
        assert_eq!(events[1].authority.as_ref(), Some(&authority));
        assert_eq!(events[1].realized_spend_units, 75);
    }

    #[test]
    fn denied_authorize_hold_reports_guarantee_metadata_without_commit_index() {
        let store = InMemoryBudgetStore::new();
        let authority = BudgetEventAuthority {
            authority_id: "kernel:test-authority".to_string(),
            lease_id: "single-node".to_string(),
            lease_epoch: 0,
        };

        let decision = store
            .authorize_budget_hold(BudgetAuthorizeHoldRequest {
                capability_id: "cap-budget-deny".to_string(),
                grant_index: 0,
                max_invocations: Some(1),
                requested_exposure_units: 150,
                max_cost_per_invocation: Some(100),
                max_total_cost_units: Some(1_000),
                hold_id: Some("hold-budget-deny".to_string()),
                event_id: Some("hold-budget-deny:authorize".to_string()),
                authority: Some(authority.clone()),
                payment_journal: None,
            })
            .unwrap();
        let BudgetAuthorizeHoldDecision::Denied(denied) = decision else {
            panic!("budget hold should be denied");
        };
        assert_eq!(denied.committed_cost_units_after, 0);
        assert_eq!(denied.invocation_count_after, 0);
        assert_eq!(
            denied.metadata.event_id.as_deref(),
            Some("hold-budget-deny:authorize")
        );
        assert_eq!(denied.metadata.budget_commit_index, None);
        assert_eq!(
            denied.metadata.guarantee_level,
            BudgetGuaranteeLevel::SingleNodeAtomic
        );
        assert_eq!(denied.metadata.authority.as_ref(), Some(&authority));

        let events = store
            .list_mutation_events(10, Some("cap-budget-deny"), Some(0))
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].allowed, Some(false));
        assert_eq!(events[0].authority.as_ref(), Some(&authority));
        assert!(store.get_usage("cap-budget-deny", 0).unwrap().is_none());
    }

    /// Minimal store exercising the DEFAULT `authorize_budget_hold` (unlike
    /// `InMemoryBudgetStore`, which overrides it): the grant answer and the
    /// journal write are scripted so the default impl's ordering between
    /// them is observable.
    struct JournalOrderProbeStore {
        allow: bool,
        journal_write_fails: bool,
        journal: std::sync::Mutex<Vec<crate::payment::PaymentJournalRecord>>,
        reverses: std::sync::Mutex<u32>,
    }

    impl JournalOrderProbeStore {
        fn new(allow: bool, journal_write_fails: bool) -> Self {
            Self {
                allow,
                journal_write_fails,
                journal: std::sync::Mutex::new(Vec::new()),
                reverses: std::sync::Mutex::new(0),
            }
        }

        fn journal_rows(&self) -> usize {
            self.journal.lock().unwrap().len()
        }

        fn reverse_count(&self) -> u32 {
            *self.reverses.lock().unwrap()
        }
    }

    impl BudgetStore for JournalOrderProbeStore {
        fn try_increment(
            &self,
            _capability_id: &str,
            _grant_index: usize,
            _max_invocations: Option<u32>,
        ) -> Result<bool, BudgetStoreError> {
            Ok(self.allow)
        }

        fn try_charge_cost(
            &self,
            _capability_id: &str,
            _grant_index: usize,
            _max_invocations: Option<u32>,
            _cost_units: u64,
            _max_cost_per_invocation: Option<u64>,
            _max_total_cost_units: Option<u64>,
        ) -> Result<bool, BudgetStoreError> {
            Ok(self.allow)
        }

        fn reverse_charge_cost(
            &self,
            _capability_id: &str,
            _grant_index: usize,
            _cost_units: u64,
        ) -> Result<(), BudgetStoreError> {
            *self.reverses.lock().unwrap() += 1;
            Ok(())
        }

        fn reduce_charge_cost(
            &self,
            _capability_id: &str,
            _grant_index: usize,
            _cost_units: u64,
        ) -> Result<(), BudgetStoreError> {
            Ok(())
        }

        fn settle_charge_cost(
            &self,
            _capability_id: &str,
            _grant_index: usize,
            _exposed_cost_units: u64,
            _realized_cost_units: u64,
        ) -> Result<(), BudgetStoreError> {
            Ok(())
        }

        fn list_usages(
            &self,
            _limit: usize,
            _capability_id: Option<&str>,
        ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
            Ok(Vec::new())
        }

        fn get_usage(
            &self,
            _capability_id: &str,
            _grant_index: usize,
        ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
            Ok(None)
        }

        fn record_payment_journal(
            &self,
            entry: &crate::payment::PaymentJournalRecord,
        ) -> Result<(), BudgetStoreError> {
            if self.journal_write_fails {
                return Err(BudgetStoreError::Invariant(
                    "journal write scripted to fail".to_string(),
                ));
            }
            self.journal.lock().unwrap().push(entry.clone());
            Ok(())
        }
    }

    fn probe_hold_request() -> BudgetAuthorizeHoldRequest {
        BudgetAuthorizeHoldRequest {
            capability_id: "cap-journal-order".to_string(),
            grant_index: 0,
            max_invocations: Some(1),
            requested_exposure_units: 100,
            max_cost_per_invocation: Some(100),
            max_total_cost_units: Some(1_000),
            hold_id: Some("hold-journal-order".to_string()),
            event_id: Some("hold-journal-order:authorize".to_string()),
            authority: None,
            payment_journal: Some(crate::payment::PaymentJournalRecord {
                request_id: "req-journal-order".to_string(),
                capability_id: "cap-journal-order".to_string(),
                grant_index: 0,
                hold_id: Some("hold-journal-order".to_string()),
                rail: "x402".to_string(),
                authorization_id: None,
                transaction_id: None,
                amount_units: 100,
                settle_action: None,
                settle_amount_units: None,
                currency: "USD".to_string(),
                state: crate::payment::PaymentJournalState::HoldPlaced,
                created_at_unix_ms: 1,
                tenant_id: None,
            }),
        }
    }

    #[test]
    fn default_authorize_hold_journals_nothing_on_a_budget_deny() {
        let store = JournalOrderProbeStore::new(false, false);
        let decision = store.authorize_budget_hold(probe_hold_request()).unwrap();
        assert!(
            matches!(decision, BudgetAuthorizeHoldDecision::Denied(_)),
            "the scripted store denies the hold"
        );
        assert_eq!(
            store.journal_rows(),
            0,
            "a budget-denied request must leave no journal row: no rail call will follow"
        );
    }

    #[test]
    fn default_authorize_hold_journals_only_a_granted_hold() {
        let store = JournalOrderProbeStore::new(true, false);
        let decision = store.authorize_budget_hold(probe_hold_request()).unwrap();
        assert!(matches!(
            decision,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        assert_eq!(store.journal_rows(), 1);
        assert_eq!(store.reverse_count(), 0);
    }

    #[test]
    fn default_authorize_hold_revokes_the_grant_when_the_journal_write_fails() {
        let store = JournalOrderProbeStore::new(true, true);
        let error = store
            .authorize_budget_hold(probe_hold_request())
            .expect_err("a granted hold whose journal cannot persist must fail closed");
        assert!(error.to_string().contains("journal write scripted to fail"));
        assert_eq!(store.journal_rows(), 0);
        assert_eq!(
            store.reverse_count(),
            1,
            "the grant must be rolled back so no hold runs without its crash record"
        );
    }
}
