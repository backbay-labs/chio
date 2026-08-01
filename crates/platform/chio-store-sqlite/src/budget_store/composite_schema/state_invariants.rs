use super::super::*;
use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq)]
struct CumulativeHistoryCounters {
    reserved: u64,
    captured: u64,
    version: u64,
}

struct CumulativeHistoryEvent {
    event_id: String,
    operation_id: String,
    kind: String,
    authorization_outcome: Option<String>,
    approval_set_digest: Option<String>,
    state_before: Option<String>,
    state_after: String,
    before: CumulativeHistoryCounters,
    after: CumulativeHistoryCounters,
    requested_authorized: u64,
    effective_threshold: u64,
}

#[derive(Clone)]
struct CumulativeHistoryFrontier {
    state: BudgetCumulativeApprovalState,
    approval_set_digest: Option<String>,
    approval_required: bool,
    admitted: bool,
}

pub(super) fn verify_budget_state_invariants(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    SqliteBudgetStore::verify_durable_usage_chains(connection)?;
    SqliteBudgetStore::verify_global_budget_authority_chain(connection)?;
    verify_provisioned_usage_coverage(connection)?;
    verify_structured_hold_event_heads(connection)?;
    verify_structured_lifecycle_history(connection)?;
    verify_cross_history_bindings(connection)?;
    verify_quota_history(connection)?;
    verify_cumulative_history(connection)?;
    verify_supplemental_capture_time(connection)?;
    verify_budget_authority_provenance(connection)?;
    verify_revocation_provenance(connection)?;
    Ok(())
}

fn verify_structured_lifecycle_history(connection: &Connection) -> Result<(), BudgetStoreError> {
    let invalid: Option<String> = connection
        .query_row(
            r#"
            WITH ordered AS (
                SELECT event.*,
                       LAG(invocation_state_after) OVER history AS previous_invocation,
                       LAG(monetary_state_after) OVER history AS previous_monetary
                FROM budget_mutation_events AS event
                WHERE projection_kind = 'composite_v1'
                WINDOW history AS (PARTITION BY hold_id ORDER BY event_seq)
            )
            SELECT event_id FROM ordered
            WHERE (
                previous_invocation IS NULL
                AND kind NOT IN ('reserve_invocation', 'authorize_exposure')
            ) OR (
                previous_invocation IS NOT NULL
                AND (invocation_state_before <> previous_invocation
                     OR monetary_state_before <> previous_monetary)
            ) OR NOT (
                (kind IN ('reserve_invocation', 'authorize_exposure')
                 AND invocation_state_before = 'absent'
                 AND monetary_state_before = 'none'
                 AND (
                    (authorization_outcome IN ('authorized', 'approval_required')
                     AND invocation_state_after = 'authorized'
                     AND monetary_state_after = CASE
                         WHEN exposure_units = 0 THEN 'none' ELSE 'exposed' END)
                    OR
                    (authorization_outcome = 'denied'
                     AND invocation_state_after = 'denied'
                     AND monetary_state_after = 'none')
                 ))
                OR (kind = 'capture_invocation'
                    AND invocation_state_before = 'authorized'
                    AND invocation_state_after = 'captured'
                    AND monetary_state_after = monetary_state_before)
                OR (kind = 'authorize_cumulative_approval'
                    AND authorization_outcome = 'authorized'
                    AND invocation_state_after = invocation_state_before
                    AND monetary_state_after = monetary_state_before)
                OR (kind IN ('reverse_invocation', 'reverse_exposure')
                    AND invocation_state_before = 'authorized'
                    AND invocation_state_after = 'reversed'
                    AND monetary_state_after = CASE
                        WHEN exposure_units = 0 THEN 'none' ELSE 'reversed' END)
                OR (kind = 'cancel_captured_before_dispatch'
                    AND invocation_state_before = 'captured'
                    AND invocation_state_after = 'reversed'
                    AND monetary_state_after = CASE
                        WHEN exposure_units = 0 THEN 'none' ELSE 'reversed' END)
                OR (kind = 'release_exposure'
                    AND invocation_state_before = 'authorized'
                    AND invocation_state_after = 'authorized'
                    AND monetary_state_before IN ('none', 'exposed')
                    AND monetary_state_after IN ('none', 'exposed', 'released'))
                OR (kind IN ('reconcile_spend', 'capture_spend')
                    AND invocation_state_before = 'captured'
                    AND invocation_state_after = 'captured'
                    AND monetary_state_before = 'exposed'
                    AND monetary_state_after = CASE kind
                        WHEN 'capture_spend' THEN 'captured' ELSE 'reconciled' END)
            )
            LIMIT 1
            "#,
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(event_id) = invalid {
        return Err(BudgetStoreError::Invariant(format!(
            "structured budget event `{event_id}` breaks hold lifecycle history"
        )));
    }
    Ok(())
}

fn verify_provisioned_usage_coverage(connection: &Connection) -> Result<(), BudgetStoreError> {
    if !table_exists(connection, "chio_serving_owner")? {
        return Ok(());
    }
    let invalid: bool = connection.query_row(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM capability_grant_budgets AS usage
            WHERE NOT EXISTS (
                SELECT 1 FROM budget_usage_history_anchors AS anchor
                WHERE anchor.capability_id = usage.capability_id
                  AND anchor.grant_index = usage.grant_index
            ) AND NOT EXISTS (
                SELECT 1 FROM budget_mutation_events AS event
                WHERE event.capability_id = usage.capability_id
                  AND event.grant_index = usage.grant_index
                  AND event.usage_seq = event.event_seq
            )
        )
        "#,
        [],
        |row| row.get(0),
    )?;
    if invalid {
        return Err(BudgetStoreError::Invariant(
            "provisioned budget usage lacks an immutable history anchor or event chain".to_string(),
        ));
    }
    Ok(())
}

fn verify_structured_hold_event_heads(connection: &Connection) -> Result<(), BudgetStoreError> {
    let invalid: Option<String> = connection
        .query_row(
            r#"
            WITH ranked AS (
                SELECT event_id, hold_id, invocation_state_after,
                       monetary_state_after, authority_id, lease_id, lease_epoch,
                       ROW_NUMBER() OVER (
                           PARTITION BY hold_id ORDER BY event_seq DESC
                       ) AS rank
                FROM budget_mutation_events
                WHERE hold_id IS NOT NULL
            )
            SELECT hold.hold_id
            FROM budget_authorization_holds AS hold
            LEFT JOIN ranked AS event
              ON event.hold_id = hold.hold_id AND event.rank = 1
            WHERE hold.projection_kind = 'composite_v1'
              AND (
                event.event_id IS NULL
                OR hold.invocation_state IS NULL
                OR hold.monetary_state IS NULL
                OR hold.invocation_state <> event.invocation_state_after
                OR hold.monetary_state <> event.monetary_state_after
                OR hold.authority_id IS NOT event.authority_id
                OR hold.lease_id IS NOT event.lease_id
                OR hold.lease_epoch IS NOT event.lease_epoch
                OR hold.invocation_count_debited <> 1
                OR hold.invocation_captured <>
                     CASE WHEN event.invocation_state_after = 'captured' THEN 1 ELSE 0 END
                OR hold.authorized_exposure_units <> (
                    SELECT authorization.exposure_units
                    FROM budget_mutation_events AS authorization
                    WHERE authorization.hold_id = hold.hold_id
                      AND authorization.kind IN (
                          'reserve_invocation', 'authorize_exposure'
                      )
                      AND authorization.authorization_outcome <> 'denied'
                    ORDER BY authorization.event_seq LIMIT 1
               )
                OR hold.remaining_exposure_units <> CASE
                    WHEN event.monetary_state_after IN (
                        'reversed', 'reconciled', 'captured'
                    ) THEN 0
                    ELSE hold.authorized_exposure_units - COALESCE((
                        SELECT SUM(release.exposure_units)
                        FROM budget_mutation_events AS release
                        WHERE release.hold_id = hold.hold_id
                          AND release.kind = 'release_exposure'
                    ), 0)
                  END
                OR hold.disposition <> CASE
                    WHEN event.invocation_state_after = 'reversed' THEN 'reversed'
                    WHEN event.monetary_state_after IN ('reconciled', 'captured')
                        THEN 'reconciled'
                    WHEN event.monetary_state_after = 'released' THEN 'released'
                    ELSE 'open'
                  END
              )
            LIMIT 1
            "#,
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(hold_id) = invalid {
        return Err(BudgetStoreError::Invariant(format!(
            "budget hold `{hold_id}` does not match its durable event frontier"
        )));
    }
    Ok(())
}

fn verify_cross_history_bindings(connection: &Connection) -> Result<(), BudgetStoreError> {
    let invalid: Option<String> = connection
        .query_row(
            r#"
            SELECT event.event_id
            FROM budget_mutation_events AS event
            JOIN budget_authorization_holds AS hold ON hold.hold_id = event.hold_id
            WHERE event.projection_kind = 'composite_v1'
              AND hold.projection_kind = 'composite_v1'
              AND (
                event.operation_id <> hold.operation_id
                OR event.revocation_set_digest <> hold.revocation_set_digest
                OR event.expected_revocation_count <> hold.expected_revocation_count
                OR event.expected_quota_count <> hold.expected_quota_count
                OR event.expected_artifact_count <> hold.expected_artifact_count
                OR event.has_cumulative_approval <> hold.has_cumulative_approval
                OR event.has_revocation_commit <> hold.has_revocation_commit
                OR event.supplemental_verifier_id IS NOT hold.supplemental_verifier_id
                OR event.supplemental_verifier_config_digest
                    IS NOT hold.supplemental_verifier_config_digest
                OR event.supplemental_artifact_digest
                    IS NOT hold.supplemental_artifact_digest
                OR event.supplemental_expires_at IS NOT hold.supplemental_expires_at
                OR EXISTS (
                    SELECT capability_id FROM budget_event_revocation_members
                    WHERE event_id = event.event_id
                    EXCEPT
                    SELECT capability_id FROM budget_hold_revocation_members
                    WHERE hold_id = hold.hold_id
                )
                OR EXISTS (
                    SELECT capability_id FROM budget_hold_revocation_members
                    WHERE hold_id = hold.hold_id
                    EXCEPT
                    SELECT capability_id FROM budget_event_revocation_members
                    WHERE event_id = event.event_id
                )
                OR EXISTS (
                    SELECT artifact_digest FROM budget_event_authorization_artifacts
                    WHERE event_id = event.event_id
                    EXCEPT
                    SELECT artifact_digest FROM budget_hold_authorization_artifacts
                    WHERE hold_id = hold.hold_id
                )
                OR EXISTS (
                    SELECT artifact_digest FROM budget_hold_authorization_artifacts
                    WHERE hold_id = hold.hold_id
                    EXCEPT
                    SELECT artifact_digest FROM budget_event_authorization_artifacts
                    WHERE event_id = event.event_id
                )
                OR EXISTS (
                    SELECT profile, owner_id, grant_index, max_invocations
                    FROM budget_event_quota_members WHERE event_id = event.event_id
                    EXCEPT
                    SELECT profile, owner_id, grant_index, max_invocations
                    FROM budget_hold_quota_members WHERE hold_id = hold.hold_id
                )
                OR EXISTS (
                    SELECT profile, owner_id, grant_index, max_invocations
                    FROM budget_hold_quota_members WHERE hold_id = hold.hold_id
                    EXCEPT
                    SELECT profile, owner_id, grant_index, max_invocations
                    FROM budget_event_quota_members WHERE event_id = event.event_id
                )
                OR EXISTS (
                    SELECT authority_id, lease_id, lease_epoch,
                           guarantee_level, commit_index
                    FROM budget_event_revocation_commits WHERE event_id = event.event_id
                    EXCEPT
                    SELECT authority_id, lease_id, lease_epoch,
                           guarantee_level, commit_index
                    FROM budget_hold_revocation_commits WHERE hold_id = hold.hold_id
                )
                OR EXISTS (
                    SELECT authority_id, lease_id, lease_epoch,
                           guarantee_level, commit_index
                    FROM budget_hold_revocation_commits WHERE hold_id = hold.hold_id
                    EXCEPT
                    SELECT authority_id, lease_id, lease_epoch,
                           guarantee_level, commit_index
                    FROM budget_event_revocation_commits WHERE event_id = event.event_id
                )
              )
            LIMIT 1
            "#,
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(event_id) = invalid {
        return Err(BudgetStoreError::Invariant(format!(
            "budget event `{event_id}` changed its hold admission binding"
        )));
    }

    let missing_parent: Option<String> = connection
        .query_row(
            r#"
            SELECT owner_id FROM (
                SELECT hold_id AS owner_id, capability_id
                FROM budget_authorization_holds
                WHERE projection_kind = 'composite_v1'
                UNION ALL
                SELECT event_id, capability_id FROM budget_mutation_events
                WHERE projection_kind = 'composite_v1'
            ) AS parent
            WHERE NOT EXISTS (
                SELECT 1 FROM budget_hold_revocation_members
                WHERE hold_id = parent.owner_id
                  AND capability_id = parent.capability_id
                UNION ALL
                SELECT 1 FROM budget_event_revocation_members
                WHERE event_id = parent.owner_id
                  AND capability_id = parent.capability_id
            )
            LIMIT 1
            "#,
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(owner_id) = missing_parent {
        return Err(BudgetStoreError::Invariant(format!(
            "composite budget projection `{owner_id}` omitted its parent capability"
        )));
    }
    Ok(())
}

fn verify_quota_history(connection: &Connection) -> Result<(), BudgetStoreError> {
    let broken_chain: Option<String> = connection
        .query_row(
            r#"
            WITH ordered AS (
                SELECT member.event_id, member.profile, member.owner_id,
                       member.grant_index, member.reserved_before,
                       member.captured_before, member.reserved_after,
                       member.captured_after, member.max_invocations,
                       event.kind, event.authorization_outcome, event.event_seq,
                       LAG(member.reserved_after) OVER (
                           PARTITION BY member.profile, member.owner_id, member.grant_index
                           ORDER BY event.event_seq
                       ) AS previous_reserved,
                       LAG(member.captured_after) OVER (
                           PARTITION BY member.profile, member.owner_id, member.grant_index
                           ORDER BY event.event_seq
                       ) AS previous_captured
                FROM budget_event_quota_members AS member
                JOIN budget_mutation_events AS event ON event.event_id = member.event_id
            )
            SELECT event_id FROM ordered
            WHERE (previous_reserved IS NULL AND (
                    reserved_before <> 0 OR captured_before <> CASE
                        WHEN profile = 'chio.grant-invocation.v1' THEN COALESCE((
                            SELECT legacy.invocation_count_after
                            FROM budget_mutation_events AS legacy
                            WHERE legacy.projection_kind = 'legacy'
                              AND legacy.capability_id = ordered.owner_id
                              AND legacy.grant_index = ordered.grant_index
                              AND legacy.event_seq < ordered.event_seq
                            ORDER BY legacy.event_seq DESC LIMIT 1
                        ), 0)
                        ELSE 0
                    END
                  ))
               OR (previous_reserved IS NOT NULL AND (
                    reserved_before <> previous_reserved
                    OR captured_before <> previous_captured
                  ))
               OR NOT (
                    (kind IN ('reserve_invocation', 'authorize_exposure')
                     AND authorization_outcome = 'denied'
                     AND reserved_after = reserved_before
                     AND captured_after = captured_before)
                    OR
                    (kind IN ('reserve_invocation', 'authorize_exposure')
                     AND authorization_outcome IN ('authorized', 'approval_required')
                     AND reserved_after = reserved_before + 1
                     AND captured_after = captured_before)
                    OR
                    (kind = 'capture_invocation' AND reserved_before > 0
                     AND reserved_after = reserved_before - 1
                     AND captured_after = captured_before + 1)
                    OR
                    (kind = 'reverse_invocation' AND reserved_before > 0
                     AND reserved_after = reserved_before - 1
                     AND captured_after = captured_before)
                    OR
                    (kind = 'cancel_captured_before_dispatch' AND captured_before > 0
                     AND reserved_after = reserved_before
                     AND captured_after = captured_before - 1)
                    OR
                    (kind NOT IN (
                        'reserve_invocation', 'authorize_exposure',
                        'capture_invocation', 'reverse_invocation',
                        'cancel_captured_before_dispatch'
                     ) AND reserved_after = reserved_before
                       AND captured_after = captured_before)
                  )
            LIMIT 1
            "#,
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(event_id) = broken_chain {
        return Err(BudgetStoreError::Invariant(format!(
            "budget event `{event_id}` breaks a quota counter chain"
        )));
    }

    let broken_bridge: Option<String> = connection
        .query_row(
            r#"
            WITH first_grant_quota AS (
                SELECT member.*, event.event_seq,
                       ROW_NUMBER() OVER (
                           PARTITION BY member.owner_id, member.grant_index
                           ORDER BY event.event_seq
                       ) AS rank
                FROM budget_event_quota_members AS member
                JOIN budget_mutation_events AS event ON event.event_id = member.event_id
                WHERE member.profile = 'chio.grant-invocation.v1'
            )
            SELECT event_id FROM first_grant_quota AS first
            WHERE rank = 1 AND (
                (captured_before > 0 AND NOT EXISTS (
                    SELECT 1 FROM budget_mutation_events AS legacy
                    WHERE legacy.projection_kind = 'legacy'
                      AND legacy.capability_id = first.owner_id
                      AND legacy.grant_index = first.grant_index
                      AND legacy.max_invocations IS NOT NULL
                ))
                OR EXISTS (
                    SELECT 1
                    FROM budget_mutation_events AS legacy
                    WHERE legacy.projection_kind = 'legacy'
                      AND legacy.capability_id = first.owner_id
                      AND legacy.grant_index = first.grant_index
                      AND legacy.max_invocations IS NOT NULL
                    GROUP BY legacy.capability_id, legacy.grant_index
                    HAVING COUNT(DISTINCT legacy.max_invocations) <> 1
                        OR MIN(legacy.max_invocations) <> first.max_invocations
                )
            )
            UNION ALL
            SELECT structured.event_id
            FROM budget_mutation_events AS structured
            WHERE structured.projection_kind = 'composite_v1'
              AND structured.kind IN ('reserve_invocation', 'authorize_exposure')
              AND EXISTS (
                  SELECT 1 FROM budget_mutation_events AS legacy
                  WHERE legacy.projection_kind = 'legacy'
                    AND legacy.capability_id = structured.capability_id
                    AND legacy.grant_index = structured.grant_index
                    AND legacy.max_invocations IS NOT NULL
              )
              AND NOT EXISTS (
                  SELECT 1 FROM budget_event_quota_members AS member
                  WHERE member.event_id = structured.event_id
                    AND member.profile = 'chio.grant-invocation.v1'
                    AND member.owner_id = structured.capability_id
                    AND member.grant_index = structured.grant_index
              )
            LIMIT 1
            "#,
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(event_id) = broken_bridge {
        return Err(BudgetStoreError::Invariant(format!(
            "budget event `{event_id}` breaks the legacy grant quota bridge"
        )));
    }

    let bad_current: Option<String> = connection
        .query_row(
            r#"
            SELECT quota.profile || ':' || quota.owner_id || ':' || quota.grant_index
            FROM budget_invocation_quotas AS quota
            WHERE quota.reserved_invocations <> (
                    SELECT COUNT(*) FROM budget_hold_quota_members AS member
                    JOIN budget_authorization_holds AS hold
                      ON hold.hold_id = member.hold_id
                    WHERE member.profile = quota.profile
                      AND member.owner_id = quota.owner_id
                      AND member.grant_index = quota.grant_index
                      AND hold.invocation_state = 'authorized'
                  )
               OR quota.captured_invocations <> (
                    CASE WHEN quota.profile = 'chio.grant-invocation.v1' THEN
                        COALESCE((
                            SELECT usage.invocation_count
                            FROM capability_grant_budgets AS usage
                            WHERE usage.capability_id = quota.owner_id
                              AND usage.grant_index = quota.grant_index
                        ), -1) - quota.reserved_invocations
                    ELSE (
                        SELECT COUNT(*) FROM budget_hold_quota_members AS member
                        JOIN budget_authorization_holds AS hold
                          ON hold.hold_id = member.hold_id
                        WHERE member.profile = quota.profile
                          AND member.owner_id = quota.owner_id
                          AND member.grant_index = quota.grant_index
                          AND hold.invocation_state = 'captured'
                    ) END
                  )
               OR quota.version <> (
                    SELECT COUNT(*) FROM budget_event_quota_members AS member
                    WHERE member.profile = quota.profile
                      AND member.owner_id = quota.owner_id
                      AND member.grant_index = quota.grant_index
                      AND (member.reserved_before <> member.reserved_after
                           OR member.captured_before <> member.captured_after)
                  )
               OR EXISTS (
                    SELECT 1 FROM budget_event_quota_members AS member
                    WHERE member.profile = quota.profile
                      AND member.owner_id = quota.owner_id
                      AND member.grant_index = quota.grant_index
                      AND member.max_invocations <> quota.max_invocations
                  )
            LIMIT 1
            "#,
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(identity) = bad_current {
        return Err(BudgetStoreError::Invariant(format!(
            "budget quota `{identity}` disagrees with retained holds"
        )));
    }
    Ok(())
}

fn cumulative_history_state(
    value: &str,
) -> Result<BudgetCumulativeApprovalState, BudgetStoreError> {
    match value {
        "pending_approval" => Ok(BudgetCumulativeApprovalState::PendingApproval),
        "authorized" => Ok(BudgetCumulativeApprovalState::Authorized),
        "captured" => Ok(BudgetCumulativeApprovalState::Captured),
        "reversed_before_dispatch" => Ok(BudgetCumulativeApprovalState::ReversedBeforeDispatch),
        _ => Err(BudgetStoreError::Invariant(format!(
            "unknown cumulative approval state `{value}`"
        ))),
    }
}

fn canonical_approval_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn verify_cumulative_state_machine(connection: &Connection) -> Result<(), BudgetStoreError> {
    let events = {
        let mut statement = connection.prepare(
            r#"
            SELECT event.event_id, cumulative.operation_id, event.kind,
                   event.authorization_outcome,
                   event.cumulative_approval_set_digest,
                   cumulative.state_before, cumulative.state_after,
                   cumulative.reserved_authorized_before,
                   cumulative.captured_authorized_before,
                   cumulative.version_before,
                   cumulative.reserved_authorized_after,
                   cumulative.captured_authorized_after,
                   cumulative.version_after,
                   cumulative.requested_authorized_units,
                   cumulative.effective_threshold_units
            FROM budget_event_cumulative_approval AS cumulative
            JOIN budget_mutation_events AS event
              ON event.event_id = cumulative.event_id
            ORDER BY event.event_seq
            "#,
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(CumulativeHistoryEvent {
                    event_id: row.get(0)?,
                    operation_id: row.get(1)?,
                    kind: row.get(2)?,
                    authorization_outcome: row.get(3)?,
                    approval_set_digest: row.get(4)?,
                    state_before: row.get(5)?,
                    state_after: row.get(6)?,
                    before: CumulativeHistoryCounters {
                        reserved: budget_u64_from_row(row, 7, "reserved_authorized_before")?,
                        captured: budget_u64_from_row(row, 8, "captured_authorized_before")?,
                        version: budget_u64_from_row(row, 9, "cumulative_version_before")?,
                    },
                    after: CumulativeHistoryCounters {
                        reserved: budget_u64_from_row(row, 10, "reserved_authorized_after")?,
                        captured: budget_u64_from_row(row, 11, "captured_authorized_after")?,
                        version: budget_u64_from_row(row, 12, "cumulative_version_after")?,
                    },
                    requested_authorized: budget_u64_from_row(
                        row,
                        13,
                        "requested_authorized_units",
                    )?,
                    effective_threshold: budget_u64_from_row(row, 14, "effective_threshold_units")?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };

    let mut frontiers = HashMap::<String, CumulativeHistoryFrontier>::new();
    for event in events {
        let state_before = event
            .state_before
            .as_deref()
            .map(cumulative_history_state)
            .transpose()?;
        let state_after = cumulative_history_state(&event.state_after)?;
        let version_incremented = event.before.version.checked_add(1) == Some(event.after.version);
        let counters_unchanged = event.before == event.after;
        let prior = frontiers.get(&event.operation_id).cloned();

        let (valid, approval_required, admitted) = if let Some(prior) = prior.as_ref() {
            let digest_unchanged = event.approval_set_digest == prior.approval_set_digest;
            let approved_digest_present = !prior.approval_required
                || prior
                    .approval_set_digest
                    .as_deref()
                    .is_some_and(canonical_approval_digest);
            let valid_transition = prior.admitted
                && state_before == Some(prior.state)
                && match event.kind.as_str() {
                    "authorize_cumulative_approval" => {
                        prior.approval_required
                            && prior.state == BudgetCumulativeApprovalState::PendingApproval
                            && prior.approval_set_digest.is_none()
                            && state_after == BudgetCumulativeApprovalState::Authorized
                            && event.authorization_outcome.as_deref() == Some("authorized")
                            && event
                                .approval_set_digest
                                .as_deref()
                                .is_some_and(canonical_approval_digest)
                            && event.before.reserved == event.after.reserved
                            && event.before.captured == event.after.captured
                            && version_incremented
                    }
                    "capture_invocation" => {
                        prior.state == BudgetCumulativeApprovalState::Authorized
                            && state_after == BudgetCumulativeApprovalState::Captured
                            && event.authorization_outcome.is_none()
                            && digest_unchanged
                            && approved_digest_present
                            && event
                                .before
                                .reserved
                                .checked_sub(event.requested_authorized)
                                == Some(event.after.reserved)
                            && event
                                .before
                                .captured
                                .checked_add(event.requested_authorized)
                                == Some(event.after.captured)
                            && version_incremented
                    }
                    "reverse_invocation" | "reverse_exposure" => {
                        matches!(
                            prior.state,
                            BudgetCumulativeApprovalState::PendingApproval
                                | BudgetCumulativeApprovalState::Authorized
                        ) && state_after == BudgetCumulativeApprovalState::ReversedBeforeDispatch
                            && event.authorization_outcome.is_none()
                            && digest_unchanged
                            && (prior.state != BudgetCumulativeApprovalState::Authorized
                                || approved_digest_present)
                            && event
                                .before
                                .reserved
                                .checked_sub(event.requested_authorized)
                                == Some(event.after.reserved)
                            && event.before.captured == event.after.captured
                            && version_incremented
                    }
                    "cancel_captured_before_dispatch" => {
                        prior.state == BudgetCumulativeApprovalState::Captured
                            && state_after == BudgetCumulativeApprovalState::ReversedBeforeDispatch
                            && event.authorization_outcome.is_none()
                            && digest_unchanged
                            && approved_digest_present
                            && event.before.reserved == event.after.reserved
                            && event
                                .before
                                .captured
                                .checked_sub(event.requested_authorized)
                                == Some(event.after.captured)
                            && version_incremented
                    }
                    "release_exposure" => {
                        matches!(
                            prior.state,
                            BudgetCumulativeApprovalState::PendingApproval
                                | BudgetCumulativeApprovalState::Authorized
                        ) && state_after == prior.state
                            && event.authorization_outcome.is_none()
                            && digest_unchanged
                            && (prior.state != BudgetCumulativeApprovalState::Authorized
                                || approved_digest_present)
                            && counters_unchanged
                    }
                    "reconcile_spend" | "capture_spend" => {
                        prior.state == BudgetCumulativeApprovalState::Captured
                            && state_after == BudgetCumulativeApprovalState::Captured
                            && event.authorization_outcome.is_none()
                            && digest_unchanged
                            && approved_digest_present
                            && counters_unchanged
                    }
                    _ => false,
                };
            (valid_transition, prior.approval_required, prior.admitted)
        } else {
            let prospective = event
                .before
                .reserved
                .checked_add(event.before.captured)
                .and_then(|value| value.checked_add(event.requested_authorized))
                .ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "budget event `{}` overflows cumulative approval state",
                        event.event_id
                    ))
                })?;
            let approval_required = prospective >= event.effective_threshold;
            let expected_state = if approval_required {
                BudgetCumulativeApprovalState::PendingApproval
            } else {
                BudgetCumulativeApprovalState::Authorized
            };
            let reservation_applied = event
                .before
                .reserved
                .checked_add(event.requested_authorized)
                == Some(event.after.reserved)
                && event.before.captured == event.after.captured
                && version_incremented;
            let admitted = event.authorization_outcome.as_deref() != Some("denied");
            let valid_initial = event.kind == "reserve_invocation"
                && state_before.is_none()
                && state_after == expected_state
                && event.approval_set_digest.is_none()
                && match event.authorization_outcome.as_deref() {
                    Some("denied") => counters_unchanged,
                    Some("approval_required") => approval_required && reservation_applied,
                    Some("authorized") => !approval_required && reservation_applied,
                    _ => false,
                };
            (valid_initial, approval_required, admitted)
        };

        if !valid {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event `{}` breaks the cumulative approval state machine",
                event.event_id
            )));
        }
        frontiers.insert(
            event.operation_id,
            CumulativeHistoryFrontier {
                state: state_after,
                approval_set_digest: event.approval_set_digest,
                approval_required,
                admitted,
            },
        );
    }
    Ok(())
}

fn verify_cumulative_history(connection: &Connection) -> Result<(), BudgetStoreError> {
    let broken: Option<String> = connection
        .query_row(
            r#"
            WITH ordered AS (
                SELECT cumulative.*,
                       LAG(reserved_authorized_after) OVER partitioned AS previous_reserved,
                       LAG(captured_authorized_after) OVER partitioned AS previous_captured,
                       LAG(version_after) OVER partitioned AS previous_version
                FROM budget_event_cumulative_approval AS cumulative
                JOIN budget_mutation_events AS event
                  ON event.event_id = cumulative.event_id
                WINDOW partitioned AS (
                    PARTITION BY cumulative.authority_id, cumulative.owner_id,
                                 cumulative.approval_budget_id,
                                 cumulative.approval_budget_epoch
                    ORDER BY event.event_seq
                )
            )
            SELECT event_id FROM ordered
            WHERE (previous_version IS NULL AND (
                    reserved_authorized_before <> 0
                    OR captured_authorized_before <> 0
                    OR version_before <> 0
                  ))
               OR (previous_version IS NOT NULL AND (
                    reserved_authorized_before <> previous_reserved
                    OR captured_authorized_before <> previous_captured
                    OR version_before <> previous_version
                  ))
               OR version_after < version_before
               OR version_after > version_before + 1
            LIMIT 1
            "#,
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(event_id) = broken {
        return Err(BudgetStoreError::Invariant(format!(
            "budget event `{event_id}` breaks a cumulative approval chain"
        )));
    }
    verify_cumulative_state_machine(connection)?;

    let changed_request: Option<String> = connection
        .query_row(
            r#"
            SELECT operation.operation_id
            FROM budget_cumulative_approval_operations AS operation
            JOIN budget_cumulative_approval_accounts AS account
              ON account.authority_id = operation.authority_id
             AND account.owner_id = operation.owner_id
             AND account.approval_budget_id = operation.approval_budget_id
             AND account.approval_budget_epoch = operation.approval_budget_epoch
            WHERE NOT EXISTS (
                    SELECT 1
                    FROM budget_event_cumulative_approval AS cumulative
                    JOIN budget_mutation_events AS event
                      ON event.event_id = cumulative.event_id
                    WHERE cumulative.operation_id = operation.operation_id
                      AND event.hold_id = operation.hold_id
                  )
               OR EXISTS (
                    SELECT 1
                    FROM budget_event_cumulative_approval AS cumulative
                    JOIN budget_mutation_events AS event
                      ON event.event_id = cumulative.event_id
                    WHERE (cumulative.operation_id = operation.operation_id
                           OR event.hold_id = operation.hold_id)
                      AND (
                        cumulative.operation_id <> operation.operation_id
                        OR event.hold_id IS NOT operation.hold_id
                        OR cumulative.authority_id <> operation.authority_id
                        OR cumulative.owner_id <> operation.owner_id
                        OR cumulative.approval_budget_id
                            <> operation.approval_budget_id
                        OR cumulative.approval_budget_epoch
                            <> operation.approval_budget_epoch
                        OR cumulative.root_grant_hash <> account.root_grant_hash
                        OR cumulative.delegation_root_id
                            IS NOT account.delegation_root_id
                        OR cumulative.root_binding_digest
                            IS NOT account.root_binding_digest
                        OR cumulative.currency <> account.currency
                        OR cumulative.authority_threshold_units
                            <> account.authority_threshold_units
                        OR cumulative.effective_threshold_units
                            <> operation.effective_threshold_units
                        OR cumulative.requested_authorized_units
                            <> operation.requested_authorized_units
                      )
                  )
            LIMIT 1
            "#,
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(operation_id) = changed_request {
        return Err(BudgetStoreError::Invariant(format!(
            "cumulative approval operation `{operation_id}` changed its immutable request"
        )));
    }

    let stale_operation: Option<String> = connection
        .query_row(
            r#"
            WITH latest AS (
                SELECT cumulative.operation_id, event.hold_id,
                       cumulative.state_after, cumulative.version_after,
                       event.cumulative_approval_set_digest,
                       ROW_NUMBER() OVER (
                           PARTITION BY cumulative.operation_id
                           ORDER BY event.event_seq DESC
                       ) AS rank
                FROM budget_event_cumulative_approval AS cumulative
                JOIN budget_mutation_events AS event
                  ON event.event_id = cumulative.event_id
            )
            SELECT operation.operation_id
            FROM budget_cumulative_approval_operations AS operation
            JOIN latest
              ON latest.operation_id = operation.operation_id
             AND latest.rank = 1
            JOIN budget_authorization_holds AS hold
              ON hold.hold_id = operation.hold_id
            WHERE latest.hold_id IS NOT operation.hold_id
               OR operation.state <> latest.state_after
               OR operation.account_version <> latest.version_after
               OR operation.approval_set_digest
                    IS NOT latest.cumulative_approval_set_digest
               OR hold.operation_id <> operation.operation_id
               OR hold.invocation_state <> CASE operation.state
                    WHEN 'pending_approval' THEN 'authorized'
                    WHEN 'authorized' THEN 'authorized'
                    WHEN 'captured' THEN 'captured'
                    WHEN 'reversed_before_dispatch' THEN 'reversed'
                    ELSE ''
                  END
            LIMIT 1
            "#,
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(operation_id) = stale_operation {
        return Err(BudgetStoreError::Invariant(format!(
            "cumulative approval operation `{operation_id}` disagrees with its event frontier"
        )));
    }

    let bad_account: Option<String> = connection
        .query_row(
            r#"
            SELECT account.authority_id || ':' || account.owner_id || ':'
                   || account.approval_budget_id
            FROM budget_cumulative_approval_accounts AS account
            WHERE account.reserved_authorized_units <> COALESCE((
                    SELECT SUM(requested_authorized_units)
                    FROM budget_cumulative_approval_operations AS operation
                    WHERE operation.authority_id = account.authority_id
                      AND operation.owner_id = account.owner_id
                      AND operation.approval_budget_id = account.approval_budget_id
                      AND operation.approval_budget_epoch = account.approval_budget_epoch
                      AND operation.state IN ('pending_approval', 'authorized')
                  ), 0)
               OR account.captured_authorized_units <> COALESCE((
                    SELECT SUM(requested_authorized_units)
                    FROM budget_cumulative_approval_operations AS operation
                    WHERE operation.authority_id = account.authority_id
                      AND operation.owner_id = account.owner_id
                      AND operation.approval_budget_id = account.approval_budget_id
                      AND operation.approval_budget_epoch = account.approval_budget_epoch
                      AND operation.state = 'captured'
                  ), 0)
               OR account.version <> COALESCE((
                    SELECT MAX(operation.account_version)
                    FROM budget_cumulative_approval_operations AS operation
                    WHERE operation.authority_id = account.authority_id
                      AND operation.owner_id = account.owner_id
                      AND operation.approval_budget_id = account.approval_budget_id
                      AND operation.approval_budget_epoch = account.approval_budget_epoch
                  ), 0)
            LIMIT 1
            "#,
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(identity) = bad_account {
        return Err(BudgetStoreError::Invariant(format!(
            "cumulative approval account `{identity}` disagrees with operations"
        )));
    }
    Ok(())
}

fn verify_supplemental_capture_time(connection: &Connection) -> Result<(), BudgetStoreError> {
    let invalid: Option<String> = connection
        .query_row(
            r#"
            SELECT event_id FROM budget_mutation_events
            WHERE projection_kind = 'composite_v1'
              AND kind = 'capture_invocation'
              AND supplemental_expires_at IS NOT NULL
              AND (trusted_time IS NULL OR trusted_time >= supplemental_expires_at)
            LIMIT 1
            "#,
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(event_id) = invalid {
        return Err(BudgetStoreError::Invariant(format!(
            "budget capture `{event_id}` has invalid trusted-time evidence"
        )));
    }
    let invalid_hold: Option<String> = connection
        .query_row(
            r#"
            SELECT hold.hold_id
            FROM budget_authorization_holds AS hold
            WHERE hold.projection_kind = 'composite_v1'
              AND (
                (hold.invocation_state NOT IN ('captured', 'reversed')
                 AND hold.trusted_capture_time IS NOT NULL)
                OR
                (hold.invocation_state = 'captured' AND (
                    hold.trusted_capture_time IS NULL
                    OR hold.trusted_capture_time IS NOT (
                        SELECT event.trusted_time
                        FROM budget_mutation_events AS event
                        WHERE event.hold_id = hold.hold_id
                          AND event.kind = 'capture_invocation'
                        ORDER BY event.event_seq DESC LIMIT 1
                    )
                    OR (hold.supplemental_expires_at IS NOT NULL
                        AND hold.trusted_capture_time >= hold.supplemental_expires_at)
                ))
                OR
                (hold.invocation_state = 'reversed'
                 AND hold.trusted_capture_time IS NOT NULL
                 AND (
                    hold.trusted_capture_time IS NOT (
                        SELECT event.trusted_time
                        FROM budget_mutation_events AS event
                        WHERE event.hold_id = hold.hold_id
                          AND event.kind = 'capture_invocation'
                        ORDER BY event.event_seq DESC LIMIT 1
                    )
                    OR NOT EXISTS (
                        SELECT 1 FROM budget_mutation_events AS event
                        WHERE event.hold_id = hold.hold_id
                          AND event.kind = 'cancel_captured_before_dispatch'
                    )
                 ))
              )
            LIMIT 1
            "#,
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(hold_id) = invalid_hold {
        return Err(BudgetStoreError::Invariant(format!(
            "budget hold `{hold_id}` has invalid durable capture time"
        )));
    }
    Ok(())
}

fn verify_revocation_provenance(connection: &Connection) -> Result<(), BudgetStoreError> {
    if !table_exists(connection, "chio_serving_leases")? {
        let has_commit: bool = connection.query_row(
            r#"
            SELECT EXISTS(SELECT 1 FROM budget_hold_revocation_commits)
                OR EXISTS(SELECT 1 FROM budget_event_revocation_commits)
            "#,
            [],
            |row| row.get(0),
        )?;
        if has_commit {
            return Err(BudgetStoreError::Invariant(
                "budget revocation provenance has no durable serving lease history".to_string(),
            ));
        }
        return Ok(());
    }
    let invalid: Option<(String, String)> = connection
        .query_row(
            r#"
            WITH commits AS (
                SELECT 'hold' AS owner_kind, hold_id AS owner_id,
                       authority_id, lease_id, lease_epoch,
                       guarantee_level, commit_index
                FROM budget_hold_revocation_commits
                UNION ALL
                SELECT 'event', event_id, authority_id, lease_id, lease_epoch,
                       guarantee_level, commit_index
                FROM budget_event_revocation_commits
            )
            SELECT commits.owner_kind, commits.owner_id
            FROM commits
            WHERE commits.authority_id = '' OR commits.lease_id = ''
               OR commits.lease_epoch <= 0 OR commits.commit_index <= 0
               OR commits.guarantee_level <> 'single_node_atomic'
               OR NOT EXISTS (
                    SELECT 1
                    FROM chio_serving_leases AS lease
                    JOIN admission_authority_commits AS committed
                      ON committed.commit_index = commits.commit_index
                    JOIN chio_serving_owner AS owner ON owner.singleton = 1
                    JOIN admission_authority_meta AS authority ON authority.singleton = 1
                    WHERE lease.store_uuid = commits.authority_id
                      AND lease.owner_epoch = commits.lease_epoch
                      AND lease.lease_id = commits.lease_id
                      AND commits.commit_index >= lease.start_head_index
                      AND (
                            (lease.end_head_index IS NOT NULL
                             AND commits.commit_index <= lease.end_head_index)
                            OR
                            (lease.end_head_index IS NULL
                             AND owner.store_uuid = lease.store_uuid
                             AND owner.owner_epoch = lease.owner_epoch
                             AND owner.lease_id = lease.lease_id
                             AND commits.commit_index <= authority.head_index)
                      )
               )
            LIMIT 1
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((kind, owner_id)) = invalid {
        return Err(BudgetStoreError::Invariant(format!(
            "budget {kind} `{owner_id}` has forged revocation provenance"
        )));
    }
    Ok(())
}

fn verify_budget_authority_provenance(connection: &Connection) -> Result<(), BudgetStoreError> {
    if !table_exists(connection, "chio_serving_leases")? {
        let has_structured: bool = connection.query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM budget_authorization_holds
                WHERE projection_kind = 'composite_v1'
            ) OR EXISTS(
                SELECT 1 FROM budget_mutation_events
                WHERE projection_kind = 'composite_v1'
            )
            "#,
            [],
            |row| row.get(0),
        )?;
        if has_structured {
            return Err(BudgetStoreError::Invariant(
                "structured budget authority has no durable serving lease history".to_string(),
            ));
        }
        return Ok(());
    }
    let invalid: Option<(String, String)> = connection
        .query_row(
            r#"
            WITH authorities AS (
                SELECT 'hold' AS owner_kind, hold_id AS owner_id,
                       authority_id, lease_id, lease_epoch
                FROM budget_authorization_holds
                WHERE projection_kind = 'composite_v1'
                UNION ALL
                SELECT 'event', event_id, authority_id, lease_id, lease_epoch
                FROM budget_mutation_events
                WHERE projection_kind = 'composite_v1'
            )
            SELECT owner_kind, owner_id
            FROM authorities
            WHERE authority_id IS NULL OR authority_id = ''
               OR lease_id IS NULL OR lease_id = ''
               OR lease_epoch IS NULL OR lease_epoch <= 0
               OR NOT EXISTS (
                    SELECT 1 FROM chio_serving_leases AS lease
                    WHERE lease.store_uuid = authorities.authority_id
                      AND lease.owner_epoch = authorities.lease_epoch
                      AND lease.lease_id = authorities.lease_id
               )
            LIMIT 1
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((kind, owner_id)) = invalid {
        return Err(BudgetStoreError::Invariant(format!(
            "structured budget {kind} `{owner_id}` has forged serving authority"
        )));
    }
    Ok(())
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool, BudgetStoreError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
            params![table],
            |row| row.get(0),
        )
        .map_err(Into::into)
}
