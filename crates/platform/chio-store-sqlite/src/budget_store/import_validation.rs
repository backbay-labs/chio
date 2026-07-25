use super::*;
use std::collections::{BTreeMap, HashMap};

type UsageIdentity = (String, u32);
type UsageState = (u32, u64, u64);

impl SqliteBudgetStore {
    pub(super) fn verify_global_budget_authority_chain(
        connection: &Connection,
    ) -> Result<(), BudgetStoreError> {
        let event_ids = {
            let mut statement = connection
                .prepare("SELECT event_id FROM budget_mutation_events ORDER BY event_seq")?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        let mut previous: Option<BudgetMutationRecord> = None;
        for event_id in event_ids {
            let event = Self::load_mutation_event(connection, &event_id)?.ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "budget event `{event_id}` disappeared during authority verification"
                ))
            })?;
            if let Some(previous) = previous.as_ref() {
                validate_usage_authority_progression(previous, &event)?;
            }
            previous = Some(event);
        }
        Ok(())
    }

    pub(super) fn install_snapshot_usage_anchors(
        transaction: &rusqlite::Transaction<'_>,
        anchors: &[BudgetUsageRecord],
        allow_verified_install: bool,
    ) -> Result<(), BudgetStoreError> {
        let mut identities = BTreeMap::new();
        for anchor in anchors {
            let identity = (anchor.capability_id.clone(), anchor.grant_index);
            if identities.insert(identity.clone(), ()).is_some() {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget snapshot repeats history anchor `{}` grant {}",
                    identity.0, identity.1
                )));
            }
            if let Some(existing) =
                load_usage_anchor(transaction, &anchor.capability_id, anchor.grant_index)?
            {
                if existing != *anchor {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget history anchor `{}` grant {} changed",
                        anchor.capability_id, anchor.grant_index
                    )));
                }
            } else if allow_verified_install {
                transaction.execute(
                    "INSERT OR IGNORE INTO budget_usage_anchor_migration_gate(singleton) VALUES (1)",
                    [],
                )?;
                transaction.execute(
                    r#"
                    INSERT INTO budget_usage_history_anchors (
                        capability_id, grant_index, invocation_count, updated_at, seq,
                        total_cost_exposed, total_cost_realized_spend,
                        anchored_schema_version
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 6)
                    "#,
                    params![
                        &anchor.capability_id,
                        i64::from(anchor.grant_index),
                        i64::from(anchor.invocation_count),
                        anchor.updated_at,
                        budget_u64_to_sqlite(anchor.seq, "anchor_seq")?,
                        budget_u64_to_sqlite(
                            anchor.total_cost_exposed,
                            "anchor_total_cost_exposed"
                        )?,
                        budget_u64_to_sqlite(
                            anchor.total_cost_realized_spend,
                            "anchor_total_cost_realized_spend"
                        )?,
                    ],
                )?;
                transaction.execute("DELETE FROM budget_usage_anchor_migration_gate", [])?;
            } else {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget history anchor `{}` grant {} has no identical locally migration-anchored state; a fresh follower must use the elected-leader snapshot path with verified anchor provenance",
                    anchor.capability_id, anchor.grant_index
                )));
            }
        }
        Ok(())
    }

    pub(super) fn validate_import_event_shape(
        event: &BudgetMutationRecord,
    ) -> Result<(), BudgetStoreError> {
        if event.event_id.is_empty()
            || event.capability_id.is_empty()
            || event.hold_id.as_deref() == Some("")
            || event.event_seq == 0
            || event.usage_seq == Some(0)
            || event
                .usage_seq
                .is_some_and(|usage_seq| usage_seq > event.event_seq)
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event `{}` has an invalid sequence binding",
                event.event_id
            )));
        }
        if let Some(authority) = event.authority.as_ref() {
            if authority.authority_id.is_empty()
                || authority.lease_id.is_empty()
                || authority.lease_epoch == 0
            {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget event `{}` has an invalid authority binding",
                    event.event_id
                )));
            }
        }
        let has_hold = event
            .hold_id
            .as_ref()
            .is_some_and(|hold_id| !hold_id.is_empty());
        let max_cost_fields_absent =
            event.max_cost_per_invocation.is_none() && event.max_total_cost_units.is_none();
        let valid = match event.kind {
            BudgetMutationKind::IncrementInvocation => {
                !has_hold
                    && event.exposure_units == 0
                    && event.realized_spend_units == 0
                    && max_cost_fields_absent
            }
            BudgetMutationKind::AuthorizeExposure => event.realized_spend_units == 0,
            BudgetMutationKind::ReserveInvocation => {
                let valid_outcome = matches!(
                    (event.authorization_outcome, event.allowed),
                    (Some(BudgetAuthorizationOutcome::Authorized), Some(true))
                        | (Some(BudgetAuthorizationOutcome::ApprovalRequired), None)
                        | (Some(BudgetAuthorizationOutcome::Denied), Some(false))
                );
                has_hold && event.realized_spend_units == 0 && valid_outcome
            }
            BudgetMutationKind::CaptureInvocation
            | BudgetMutationKind::CancelCapturedBeforeDispatch => {
                has_hold
                    && event.realized_spend_units == 0
                    && event.max_invocations.is_none()
                    && max_cost_fields_absent
            }
            BudgetMutationKind::ReverseExposure
            | BudgetMutationKind::ReverseInvocation
            | BudgetMutationKind::ReleaseExposure => {
                event.realized_spend_units == 0
                    && event.max_invocations.is_none()
                    && max_cost_fields_absent
                    && (event.kind != BudgetMutationKind::ReverseInvocation || has_hold)
            }
            BudgetMutationKind::ReconcileSpend | BudgetMutationKind::CaptureSpend => {
                event.realized_spend_units <= event.exposure_units
                    && event.max_invocations.is_none()
                    && max_cost_fields_absent
                    && (event.kind != BudgetMutationKind::CaptureSpend || has_hold)
            }
            BudgetMutationKind::AuthorizeCumulativeApproval => {
                has_hold
                    && event.exposure_units == 0
                    && event.realized_spend_units == 0
                    && event.max_invocations.is_none()
                    && max_cost_fields_absent
            }
        };
        if !valid {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event `{}` has an invalid imported mutation shape",
                event.event_id
            )));
        }
        Ok(())
    }

    pub(super) fn verify_durable_usage_chains(
        connection: &rusqlite::Connection,
    ) -> Result<(), BudgetStoreError> {
        let identities = {
            let mut statement = connection.prepare(
                r#"
                SELECT DISTINCT capability_id, grant_index
                FROM (
                    SELECT capability_id, grant_index FROM budget_mutation_events
                    UNION
                    SELECT capability_id, grant_index FROM budget_usage_history_anchors
                    UNION
                    SELECT capability_id, grant_index FROM capability_grant_budgets
                )
                ORDER BY capability_id, grant_index
                "#,
            )?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        budget_u32_from_row(row, 1, "grant_index")?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        for identity in identities {
            let anchor = connection
                .query_row(
                    r#"
                    SELECT capability_id, grant_index, invocation_count, updated_at, seq,
                           total_cost_exposed, total_cost_realized_spend
                    FROM budget_usage_history_anchors
                    WHERE capability_id = ?1 AND grant_index = ?2
                    "#,
                    params![&identity.0, i64::from(identity.1)],
                    record_from_row,
                )
                .optional()?;
            let anchor_seq = anchor.as_ref().map_or(0, |anchor| anchor.seq);
            let event_ids = {
                let mut statement = connection.prepare(
                    r#"
                    SELECT event_id FROM budget_mutation_events
                    WHERE capability_id = ?1 AND grant_index = ?2 AND event_seq > ?3
                    ORDER BY event_seq
                    "#,
                )?;
                let rows = statement
                    .query_map(
                        params![
                            &identity.0,
                            i64::from(identity.1),
                            budget_u64_to_sqlite(anchor_seq, "anchor_seq")?,
                        ],
                        |row| row.get::<_, String>(0),
                    )?
                    .collect::<Result<Vec<_>, _>>()?;
                rows
            };
            let mut state = anchor
                .as_ref()
                .map(|anchor| {
                    (
                        anchor.invocation_count,
                        anchor.total_cost_exposed,
                        anchor.total_cost_realized_spend,
                    )
                })
                .unwrap_or((0, 0, 0));
            let mut usage_seq = anchor.as_ref().map(|anchor| anchor.seq);
            let mut usage_updated_at = anchor.as_ref().map(|anchor| anchor.updated_at);
            let mut previous: Option<BudgetMutationRecord> = None;
            for event_id in event_ids {
                let event = Self::load_mutation_event(connection, &event_id)?.ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "budget event `{event_id}` disappeared during startup verification"
                    ))
                })?;
                Self::validate_import_event_shape(&event)?;
                let projection_kind: String = connection.query_row(
                    "SELECT projection_kind FROM budget_mutation_events WHERE event_id = ?1",
                    params![&event.event_id],
                    |row| row.get(0),
                )?;
                if projection_kind == "legacy" {
                    validate_legacy_event_lifecycle(&event)?;
                }
                if let Some(previous) = previous.as_ref() {
                    validate_usage_authority_progression(previous, &event)?;
                }
                let expected = expected_usage_after(&event, state, usage_seq)?;
                if event_usage_state(&event) != expected {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget event `{}` breaks the durable usage chain",
                        event.event_id
                    )));
                }
                state = expected;
                if event_mutates_usage(&event) {
                    usage_seq = Some(event.event_seq);
                    usage_updated_at = Some(event.recorded_at);
                }
                previous = Some(event);
            }
            if let Some(usage_seq) = usage_seq {
                let current = connection
                    .query_row(
                        r#"
                        SELECT capability_id, grant_index, invocation_count, updated_at, seq,
                               total_cost_exposed, total_cost_realized_spend
                        FROM capability_grant_budgets
                        WHERE capability_id = ?1 AND grant_index = ?2
                        "#,
                        params![&identity.0, i64::from(identity.1)],
                        record_from_row,
                    )
                    .optional()?
                    .ok_or_else(|| {
                        BudgetStoreError::Invariant(format!(
                            "budget usage `{}` grant {} disappeared",
                            identity.0, identity.1
                        ))
                    })?;
                if current.seq != usage_seq
                    || Some(current.updated_at) != usage_updated_at
                    || (
                        current.invocation_count,
                        current.total_cost_exposed,
                        current.total_cost_realized_spend,
                    ) != state
                {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget usage `{}` grant {} is not the durable history head",
                        identity.0, identity.1
                    )));
                }
            }
        }
        Ok(())
    }

    pub(super) fn validate_import_batch_order(
        events: &[BudgetMutationRecord],
    ) -> Result<(), BudgetStoreError> {
        let mut last_by_identity: HashMap<UsageIdentity, u64> = HashMap::new();
        let mut previous_global: Option<&BudgetMutationRecord> = None;
        for event in events {
            if let Some(previous) = previous_global {
                if event.event_seq <= previous.event_seq {
                    return Err(BudgetStoreError::Invariant(
                        "budget import is not globally ordered by event sequence".to_string(),
                    ));
                }
                validate_usage_authority_progression(previous, event)?;
            }
            previous_global = Some(event);
            let identity = (event.capability_id.clone(), event.grant_index);
            if let Some(previous) = last_by_identity.insert(identity, event.event_seq) {
                if event.event_seq <= previous {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget import for `{}` grant {} is not ordered by event sequence",
                        event.capability_id, event.grant_index
                    )));
                }
            }
        }
        Ok(())
    }

    pub(super) fn validate_import_event_usage_chain(
        transaction: &rusqlite::Transaction<'_>,
        event: &BudgetMutationRecord,
    ) -> Result<(), BudgetStoreError> {
        let anchor = load_usage_anchor(transaction, &event.capability_id, event.grant_index)?;
        if anchor
            .as_ref()
            .is_some_and(|anchor| event.event_seq <= anchor.seq)
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event `{}` does not advance immutable history anchor",
                event.event_id
            )));
        }
        let global_predecessor = load_global_neighbor_event(transaction, event, "<", "DESC")?;
        if let Some(predecessor) = global_predecessor.as_ref() {
            validate_usage_authority_progression(predecessor, event)?;
        }
        if let Some(successor) = load_global_neighbor_event(transaction, event, ">", "ASC")? {
            validate_usage_authority_progression(event, &successor)?;
        }
        let predecessor = load_neighbor_usage_event(transaction, event, "<", "DESC")?.filter(
            |(predecessor, _)| {
                anchor
                    .as_ref()
                    .is_none_or(|anchor| predecessor.event_seq > anchor.seq)
            },
        );
        let before = predecessor
            .as_ref()
            .map(|value| value.1)
            .or_else(|| {
                anchor.as_ref().map(|anchor| {
                    (
                        anchor.invocation_count,
                        anchor.total_cost_exposed,
                        anchor.total_cost_realized_spend,
                    )
                })
            })
            .unwrap_or((0, 0, 0));
        let previous_usage_seq = latest_usage_mutation_seq_before(transaction, event)?
            .filter(|seq| anchor.as_ref().is_none_or(|anchor| *seq > anchor.seq))
            .or_else(|| anchor.as_ref().map(|anchor| anchor.seq));
        let expected = expected_usage_after(event, before, previous_usage_seq)?;
        let actual = event_usage_state(event);
        if actual != expected {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event `{}` counters do not follow the durable usage chain",
                event.event_id
            )));
        }

        if let Some((successor, _)) = load_neighbor_usage_event(transaction, event, ">", "ASC")? {
            let next_usage_seq = if event_mutates_usage(event) {
                Some(event.event_seq)
            } else {
                previous_usage_seq
            };
            let successor_expected = expected_usage_after(&successor, actual, next_usage_seq)?;
            if event_usage_state(&successor) != successor_expected {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget event `{}` would break successor `{}` usage chain",
                    event.event_id, successor.event_id
                )));
            }
        }
        Ok(())
    }

    pub(super) fn reconcile_imported_usages(
        transaction: &rusqlite::Transaction<'_>,
        usages: &[BudgetUsageRecord],
        events: &[BudgetMutationRecord],
    ) -> Result<(), BudgetStoreError> {
        let mut page_heads: BTreeMap<UsageIdentity, u64> = BTreeMap::new();
        for event in events.iter().filter(|event| event_mutates_usage(event)) {
            page_heads.insert(
                (event.capability_id.clone(), event.grant_index),
                event.event_seq,
            );
        }

        let mut supplied: BTreeMap<UsageIdentity, &BudgetUsageRecord> = BTreeMap::new();
        for usage in usages {
            let identity = (usage.capability_id.clone(), usage.grant_index);
            if supplied.insert(identity.clone(), usage).is_some() {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget snapshot repeats usage `{}` grant {}",
                    identity.0, identity.1
                )));
            }
            if let Some(expected_seq) = page_heads.get(&identity).copied() {
                validate_usage_matches_event(transaction, usage, Some(expected_seq))?;
            } else if usage_mutation_exists(transaction, &identity, usage.seq)? {
                validate_usage_matches_event(transaction, usage, Some(usage.seq))?;
            } else if let Some(anchor) =
                load_usage_anchor(transaction, &usage.capability_id, usage.grant_index)?
            {
                if anchor != *usage {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget usage history anchor `{}` grant {} changed",
                        usage.capability_id, usage.grant_index
                    )));
                }
            } else {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget usage `{}` grant {} has no usage-mutating event or explicit history anchor",
                    identity.0, identity.1
                )));
            }
        }

        let affected: Vec<_> = page_heads.keys().chain(supplied.keys()).cloned().collect();
        for (identity, event_seq) in page_heads {
            if supplied.contains_key(&identity) {
                continue;
            }
            let derived = usage_from_event(transaction, &identity, event_seq)?;
            Self::upsert_usage_in_transaction(transaction, &derived)?;
        }
        for usage in usages {
            Self::upsert_usage_in_transaction(transaction, usage)?;
        }
        for identity in affected {
            validate_current_usage_head(transaction, &identity)?;
        }
        Ok(())
    }
}

fn load_global_neighbor_event(
    connection: &Connection,
    event: &BudgetMutationRecord,
    comparison: &str,
    order: &str,
) -> Result<Option<BudgetMutationRecord>, BudgetStoreError> {
    let event_id: Option<String> = connection
        .query_row(
            &format!(
                "SELECT event_id FROM budget_mutation_events \
                 WHERE event_seq {comparison} ?1 ORDER BY event_seq {order} LIMIT 1"
            ),
            params![budget_u64_to_sqlite(event.event_seq, "event_seq")?],
            |row| row.get(0),
        )
        .optional()?;
    event_id
        .map(|event_id| {
            SqliteBudgetStore::load_mutation_event(connection, &event_id)?.ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "global budget event neighbor `{event_id}` disappeared"
                ))
            })
        })
        .transpose()
}

fn load_usage_anchor(
    connection: &Connection,
    capability_id: &str,
    grant_index: u32,
) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
    connection
        .query_row(
            r#"
            SELECT capability_id, grant_index, invocation_count, updated_at, seq,
                   total_cost_exposed, total_cost_realized_spend
            FROM budget_usage_history_anchors
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![capability_id, i64::from(grant_index)],
            record_from_row,
        )
        .optional()
        .map_err(Into::into)
}

fn usage_mutation_exists(
    connection: &Connection,
    identity: &UsageIdentity,
    event_seq: u64,
) -> Result<bool, BudgetStoreError> {
    connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM budget_mutation_events
                WHERE capability_id = ?1 AND grant_index = ?2
                  AND event_seq = ?3 AND usage_seq = event_seq
            )
            "#,
            params![
                &identity.0,
                i64::from(identity.1),
                budget_u64_to_sqlite(event_seq, "event_seq")?,
            ],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn event_mutates_usage(event: &BudgetMutationRecord) -> bool {
    matches!(
        event.kind,
        BudgetMutationKind::IncrementInvocation
            | BudgetMutationKind::ReserveInvocation
            | BudgetMutationKind::AuthorizeExposure
            | BudgetMutationKind::CancelCapturedBeforeDispatch
            | BudgetMutationKind::ReverseInvocation
            | BudgetMutationKind::ReverseExposure
            | BudgetMutationKind::ReleaseExposure
            | BudgetMutationKind::ReconcileSpend
            | BudgetMutationKind::CaptureSpend
    ) && event.allowed != Some(false)
}

fn expected_usage_after(
    event: &BudgetMutationRecord,
    before: UsageState,
    previous_usage_seq: Option<u64>,
) -> Result<UsageState, BudgetStoreError> {
    let expected_usage_seq = if event_mutates_usage(event) {
        Some(event.event_seq)
    } else if event.allowed == Some(false) {
        None
    } else if matches!(
        event.kind,
        BudgetMutationKind::CaptureInvocation | BudgetMutationKind::AuthorizeCumulativeApproval
    ) {
        previous_usage_seq
    } else {
        return Err(BudgetStoreError::Invariant(format!(
            "budget event `{}` has no defined usage transition",
            event.event_id
        )));
    };
    if event.usage_seq != expected_usage_seq {
        return Err(BudgetStoreError::Invariant(format!(
            "budget event `{}` has an invalid usage sequence binding",
            event.event_id
        )));
    }

    let checked_add_u32 = |value: u32, delta: u32, field: &str| {
        value.checked_add(delta).ok_or_else(|| {
            BudgetStoreError::Overflow(format!("budget import {field} overflowed u32"))
        })
    };
    let checked_add_u64 = |value: u64, delta: u64, field: &str| {
        value.checked_add(delta).ok_or_else(|| {
            BudgetStoreError::Overflow(format!("budget import {field} overflowed u64"))
        })
    };
    let checked_sub_u32 = |value: u32, delta: u32, field: &str| {
        value.checked_sub(delta).ok_or_else(|| {
            BudgetStoreError::Invariant(format!("budget import {field} regressed below zero"))
        })
    };
    let checked_sub_u64 = |value: u64, delta: u64, field: &str| {
        value.checked_sub(delta).ok_or_else(|| {
            BudgetStoreError::Invariant(format!("budget import {field} regressed below zero"))
        })
    };

    match event.kind {
        BudgetMutationKind::IncrementInvocation if event.allowed == Some(true) => Ok((
            checked_add_u32(before.0, 1, "invocation count")?,
            before.1,
            before.2,
        )),
        BudgetMutationKind::AuthorizeExposure if event.allowed == Some(true) => Ok((
            checked_add_u32(before.0, 1, "invocation count")?,
            checked_add_u64(before.1, event.exposure_units, "exposed cost")?,
            before.2,
        )),
        BudgetMutationKind::ReserveInvocation
            if matches!(
                event.authorization_outcome,
                Some(BudgetAuthorizationOutcome::Authorized)
                    | Some(BudgetAuthorizationOutcome::ApprovalRequired)
            ) =>
        {
            Ok((
                checked_add_u32(before.0, 1, "invocation count")?,
                checked_add_u64(before.1, event.exposure_units, "exposed cost")?,
                before.2,
            ))
        }
        BudgetMutationKind::IncrementInvocation | BudgetMutationKind::AuthorizeExposure
            if event.allowed == Some(false) =>
        {
            Ok(before)
        }
        BudgetMutationKind::ReserveInvocation
            if event.authorization_outcome == Some(BudgetAuthorizationOutcome::Denied) =>
        {
            Ok(before)
        }
        BudgetMutationKind::CaptureInvocation | BudgetMutationKind::AuthorizeCumulativeApproval => {
            Ok(before)
        }
        BudgetMutationKind::CancelCapturedBeforeDispatch
        | BudgetMutationKind::ReverseInvocation
        | BudgetMutationKind::ReverseExposure => Ok((
            checked_sub_u32(before.0, 1, "invocation count")?,
            checked_sub_u64(before.1, event.exposure_units, "exposed cost")?,
            before.2,
        )),
        BudgetMutationKind::ReleaseExposure => Ok((
            before.0,
            checked_sub_u64(before.1, event.exposure_units, "exposed cost")?,
            before.2,
        )),
        BudgetMutationKind::ReconcileSpend | BudgetMutationKind::CaptureSpend => Ok((
            before.0,
            checked_sub_u64(before.1, event.exposure_units, "exposed cost")?,
            checked_add_u64(before.2, event.realized_spend_units, "realized spend")?,
        )),
        _ => Err(BudgetStoreError::Invariant(format!(
            "budget event `{}` has an invalid imported usage transition",
            event.event_id
        ))),
    }
}

fn event_usage_state(event: &BudgetMutationRecord) -> UsageState {
    (
        event.invocation_count_after,
        event.total_cost_exposed_after,
        event.total_cost_realized_spend_after,
    )
}

fn validate_usage_authority_progression(
    before: &BudgetMutationRecord,
    after: &BudgetMutationRecord,
) -> Result<(), BudgetStoreError> {
    match (before.authority.as_ref(), after.authority.as_ref()) {
        (None, None) => Ok(()),
        (None, Some(_)) => Ok(()),
        (Some(_), None) => Err(BudgetStoreError::Invariant(format!(
            "budget event `{}` changed authority presence after `{}`",
            after.event_id, before.event_id
        ))),
        (Some(before_authority), Some(after_authority)) => {
            let invalid = after_authority.lease_epoch < before_authority.lease_epoch
                || (after_authority.lease_epoch == before_authority.lease_epoch
                    && (after_authority.authority_id != before_authority.authority_id
                        || after_authority.lease_id != before_authority.lease_id));
            if invalid {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget event `{}` has an invalid authority progression after `{}`",
                    after.event_id, before.event_id
                )));
            }
            Ok(())
        }
    }
}

fn load_neighbor_usage_event(
    transaction: &rusqlite::Transaction<'_>,
    event: &BudgetMutationRecord,
    comparison: &str,
    order: &str,
) -> Result<Option<(BudgetMutationRecord, UsageState)>, BudgetStoreError> {
    let event_id: Option<String> = transaction
        .query_row(
            &format!(
                "SELECT event_id FROM budget_mutation_events \
                 WHERE capability_id = ?1 AND grant_index = ?2 AND event_seq {comparison} ?3 \
                 ORDER BY event_seq {order} LIMIT 1"
            ),
            params![
                &event.capability_id,
                i64::from(event.grant_index),
                budget_u64_to_sqlite(event.event_seq, "event_seq")?,
            ],
            |row| row.get(0),
        )
        .optional()?;
    let Some(event_id) = event_id else {
        return Ok(None);
    };
    let neighbor =
        SqliteBudgetStore::load_mutation_event(transaction, &event_id)?.ok_or_else(|| {
            BudgetStoreError::Invariant(format!("budget usage neighbor `{event_id}` disappeared"))
        })?;
    let state = event_usage_state(&neighbor);
    Ok(Some((neighbor, state)))
}

fn latest_usage_mutation_seq_before(
    transaction: &rusqlite::Transaction<'_>,
    event: &BudgetMutationRecord,
) -> Result<Option<u64>, BudgetStoreError> {
    transaction
        .query_row(
            r#"
            SELECT event_seq FROM budget_mutation_events
            WHERE capability_id = ?1 AND grant_index = ?2
              AND event_seq < ?3 AND usage_seq = event_seq
            ORDER BY event_seq DESC LIMIT 1
            "#,
            params![
                &event.capability_id,
                i64::from(event.grant_index),
                budget_u64_to_sqlite(event.event_seq, "event_seq")?,
            ],
            |row| budget_u64_from_row(row, 0, "event_seq"),
        )
        .optional()
        .map_err(Into::into)
}

fn validate_usage_matches_event(
    transaction: &rusqlite::Transaction<'_>,
    usage: &BudgetUsageRecord,
    expected_seq: Option<u64>,
) -> Result<(), BudgetStoreError> {
    let expected_seq = expected_seq.ok_or_else(|| {
        BudgetStoreError::Invariant(format!(
            "budget usage `{}` grant {} has no durable event",
            usage.capability_id, usage.grant_index
        ))
    })?;
    if usage.seq != expected_seq {
        return Err(BudgetStoreError::Invariant(format!(
            "budget usage `{}` grant {} does not match the imported page head",
            usage.capability_id, usage.grant_index
        )));
    }
    let expected = usage_from_event(
        transaction,
        &(usage.capability_id.clone(), usage.grant_index),
        expected_seq,
    )?;
    if usage.invocation_count != expected.invocation_count
        || usage.updated_at != expected.updated_at
        || usage.total_cost_exposed != expected.total_cost_exposed
        || usage.total_cost_realized_spend != expected.total_cost_realized_spend
    {
        return Err(BudgetStoreError::Invariant(format!(
            "budget usage `{}` grant {} counters do not match event {}",
            usage.capability_id, usage.grant_index, expected_seq
        )));
    }
    Ok(())
}

fn usage_from_event(
    transaction: &rusqlite::Transaction<'_>,
    identity: &UsageIdentity,
    event_seq: u64,
) -> Result<BudgetUsageRecord, BudgetStoreError> {
    transaction
        .query_row(
            r#"
            SELECT recorded_at, invocation_count_after,
                   total_cost_exposed_after, total_cost_realized_spend_after
            FROM budget_mutation_events
            WHERE capability_id = ?1 AND grant_index = ?2
              AND event_seq = ?3 AND usage_seq = event_seq
            "#,
            params![
                &identity.0,
                i64::from(identity.1),
                budget_u64_to_sqlite(event_seq, "event_seq")?,
            ],
            |row| {
                Ok(BudgetUsageRecord {
                    capability_id: identity.0.clone(),
                    grant_index: identity.1,
                    invocation_count: budget_u32_from_row(row, 1, "invocation_count_after")?,
                    updated_at: row.get(0)?,
                    seq: event_seq,
                    total_cost_exposed: budget_u64_from_row(row, 2, "total_cost_exposed_after")?,
                    total_cost_realized_spend: budget_u64_from_row(
                        row,
                        3,
                        "total_cost_realized_spend_after",
                    )?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "budget usage `{}` grant {} does not bind a usage-mutating event at {}",
                identity.0, identity.1, event_seq
            ))
        })
}

fn validate_current_usage_head(
    transaction: &rusqlite::Transaction<'_>,
    identity: &UsageIdentity,
) -> Result<(), BudgetStoreError> {
    let event_seq = transaction
        .query_row(
            r#"
            SELECT event_seq FROM budget_mutation_events
            WHERE capability_id = ?1 AND grant_index = ?2
              AND usage_seq = event_seq
            ORDER BY event_seq DESC LIMIT 1
            "#,
            params![&identity.0, i64::from(identity.1)],
            |row| budget_u64_from_row(row, 0, "event_seq"),
        )
        .optional()?;
    let anchor = load_usage_anchor(transaction, &identity.0, identity.1)?;
    let expected = match (event_seq, anchor) {
        (Some(event_seq), Some(anchor)) if anchor.seq >= event_seq => anchor,
        (Some(event_seq), _) => usage_from_event(transaction, identity, event_seq)?,
        (None, Some(anchor)) => anchor,
        (None, None) => {
            return Err(BudgetStoreError::Invariant(format!(
                "budget usage `{}` grant {} has no history anchor or usage-mutating event",
                identity.0, identity.1
            )));
        }
    };
    let actual = transaction
        .query_row(
            r#"
            SELECT capability_id, grant_index, invocation_count, updated_at, seq,
                   total_cost_exposed, total_cost_realized_spend
            FROM capability_grant_budgets
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![&identity.0, i64::from(identity.1)],
            record_from_row,
        )
        .optional()?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "budget usage `{}` grant {} disappeared during import",
                identity.0, identity.1
            ))
        })?;
    if actual.seq != expected.seq
        || actual.invocation_count != expected.invocation_count
        || actual.updated_at != expected.updated_at
        || actual.total_cost_exposed != expected.total_cost_exposed
        || actual.total_cost_realized_spend != expected.total_cost_realized_spend
    {
        return Err(BudgetStoreError::Invariant(format!(
            "budget usage `{}` grant {} is not the durable event-chain head",
            identity.0, identity.1
        )));
    }
    Ok(())
}
