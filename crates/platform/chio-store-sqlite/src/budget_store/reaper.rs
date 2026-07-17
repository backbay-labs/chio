use super::*;

use std::collections::HashMap;

use chio_kernel::budget_store::{BudgetReconcileHoldRequest, BudgetReverseHoldRequest};

/// Outcome of a startup reap pass over orphaned open holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReapSummary {
    pub reconciled: usize,
    pub reversed: usize,
}

/// An open reserved hold past its TTL deadline:
/// `(hold_id, capability_id, grant_index, remaining_exposure_units, authority)`.
type ExpiredReservedHold = (String, String, u32, u64, Option<BudgetEventAuthority>);

/// A hold still `open` at startup:
/// `(hold_id, capability_id, grant_index, remaining_exposure_units, authority)`.
type OpenHold = (String, String, u32, u64, Option<BudgetEventAuthority>);

impl SqliteBudgetStore {
    /// Reconcile or reverse every hold still `open` at startup. Holds present in
    /// `realized_by_hold` (arbitrated by the ADR-0013 durable receipt log) are
    /// reconciled to their realized spend; holds absent from it (never durably
    /// admitted) are reversed. This is fail-closed against double-spend: a naive
    /// blanket release is never used.
    ///
    /// Called by the `BudgetStore` trait implementation of `reap_orphaned_holds`.
    pub fn reap_holds_by_map(
        &self,
        realized_by_hold: &HashMap<String, u64>,
    ) -> Result<ReapSummary, BudgetStoreError> {
        let open_holds = self.list_open_holds()?;
        let mut summary = ReapSummary {
            reconciled: 0,
            reversed: 0,
        };
        for (hold_id, capability_id, grant_index, exposure, authority) in open_holds {
            // Kernel-authored holds carry a BudgetEventAuthority lease that the
            // reconcile/reverse authority check enforces. Present each hold's stored
            // authority so orphaned kernel holds are reclaimed rather than rejected;
            // a hold whose authority columns cannot be loaded fails closed in
            // `list_open_holds` rather than silently reaping with no authority.
            match realized_by_hold.get(&hold_id) {
                Some(&realized) => {
                    self.reconcile_budget_hold(BudgetReconcileHoldRequest {
                        capability_id: capability_id.clone(),
                        grant_index: grant_index as usize,
                        exposed_cost_units: exposure,
                        realized_spend_units: realized.min(exposure),
                        hold_id: Some(hold_id.clone()),
                        event_id: Some(format!("{hold_id}:reap-reconcile")),
                        authority,
                    })?;
                    summary.reconciled += 1;
                }
                None => {
                    self.reverse_budget_hold(BudgetReverseHoldRequest {
                        capability_id: capability_id.clone(),
                        grant_index: grant_index as usize,
                        reversed_exposure_units: exposure,
                        hold_id: Some(hold_id.clone()),
                        event_id: Some(format!("{hold_id}:reap-reverse")),
                        authority,
                    })?;
                    summary.reversed += 1;
                }
            }
        }
        Ok(summary)
    }

    /// Settle every reserved hold that is still `open` and whose `reserved_until`
    /// deadline is at or before `now_unix_secs` at its reserved worst-case,
    /// forfeiting the reserved amount to realized spend. In the two-phase
    /// reserve/reconcile flow the only evidence a spend occurred is the caller's
    /// reconcile; an expired-and-unreconciled hold may correspond to a call that
    /// executed and spent, so releasing it (realized 0) would under-count real
    /// spend and fail open for a cumulative cap. The abandoning caller instead
    /// forfeits the worst-case (must reconcile before expiry to reclaim the
    /// difference). Fail-closed: only holds explicitly marked reserved (a non-NULL
    /// `reserved_until`) and past expiry are touched; a not-yet-expired reserved
    /// hold and any non-open hold are left alone. Idempotent (a settled hold is no
    /// longer open). Returns the number of holds settled.
    pub fn reap_expired_reserved_holds(
        &self,
        now_unix_secs: i64,
    ) -> Result<usize, BudgetStoreError> {
        let expired = self.list_expired_reserved_holds(now_unix_secs)?;
        let mut settled = 0usize;
        for (hold_id, capability_id, grant_index, remaining, authority) in expired {
            self.reconcile_budget_hold(BudgetReconcileHoldRequest {
                capability_id,
                grant_index: grant_index as usize,
                exposed_cost_units: remaining,
                realized_spend_units: remaining,
                hold_id: Some(hold_id.clone()),
                event_id: Some(format!("{hold_id}:ttl-reap-settle")),
                authority,
            })?;
            settled += 1;
        }
        Ok(settled)
    }

    /// Open reserved holds past their expiry:
    /// `(hold_id, capability_id, grant_index, remaining_exposure_units, authority)`.
    fn list_expired_reserved_holds(
        &self,
        now_unix_secs: i64,
    ) -> Result<Vec<ExpiredReservedHold>, BudgetStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| BudgetStoreError::Invariant("budget store mutex poisoned".to_string()))?;
        let mut statement = connection.prepare(
            "SELECT hold_id, capability_id, grant_index, remaining_exposure_units, \
             authority_id, lease_id, lease_epoch \
             FROM budget_authorization_holds \
             WHERE disposition = 'open' AND reserved_until IS NOT NULL AND reserved_until <= ?1",
        )?;
        let rows = statement.query_map([now_unix_secs], |row| {
            let authority = sqlite_budget_event_authority(row.get(4)?, row.get(5)?, row.get(6)?)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? as u32,
                row.get::<_, i64>(3)? as u64,
                authority,
            ))
        })?;
        let mut holds = Vec::new();
        for row in rows {
            holds.push(row?);
        }
        Ok(holds)
    }

    /// Stamp an open hold with a TTL reaper deadline, the grant currency, and the
    /// rail transaction id of a prepaid MustPrepay reservation (`None` when the
    /// reserve carried no prepayment). Errors fail-closed when the hold is missing
    /// or is no longer open.
    pub fn mark_hold_reserved_until(
        &self,
        hold_id: &str,
        reserved_until_unix_secs: i64,
        currency: &str,
        payment_reference: Option<&str>,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| BudgetStoreError::Invariant("budget store mutex poisoned".to_string()))?;
        let affected = connection.execute(
            "UPDATE budget_authorization_holds \
             SET reserved_until = ?2, reserved_currency = ?3, reserved_payment_reference = ?4, \
                 reserved_budget_total = ?5, reserved_delegation_depth = ?6, \
                 reserved_root_budget_holder = ?7 \
             WHERE hold_id = ?1 AND disposition = 'open'",
            params![
                hold_id,
                reserved_until_unix_secs,
                currency,
                payment_reference,
                envelope.budget_total.map(|value| value as i64),
                envelope.delegation_depth as i64,
                envelope.root_budget_holder,
            ],
        )?;
        if affected == 0 {
            return Err(BudgetStoreError::Invariant(format!(
                "cannot mark budget hold `{hold_id}` reserved: missing or not open"
            )));
        }
        Ok(())
    }

    /// Adopt an already-debited invocation into a durable zero-exposure reserved
    /// hold, stamped with the TTL deadline and no currency. The invocation was
    /// already counted by `try_increment`, so this only records the open hold
    /// (never touching the invocation count); reversing it by hold id returns the
    /// invocation, while reconciling or reaping it keeps the invocation consumed.
    /// Fails closed when a hold already exists under the id.
    pub fn reserve_invocation_hold(
        &self,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        reserved_until_unix_secs: i64,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| BudgetStoreError::Invariant("budget store mutex poisoned".to_string()))?;
        let now = unix_now();
        let inserted = connection.execute(
            "INSERT OR IGNORE INTO budget_authorization_holds ( \
                 hold_id, capability_id, grant_index, \
                 authorized_exposure_units, remaining_exposure_units, invocation_count_debited, \
                 disposition, authority_id, lease_id, lease_epoch, \
                 created_at, updated_at, reserved_until, reserved_currency, \
                 reserved_payment_reference, reserved_budget_total, \
                 reserved_delegation_depth, reserved_root_budget_holder \
             ) VALUES (?1, ?2, ?3, 0, 0, 1, 'open', NULL, NULL, NULL, ?4, ?4, ?5, NULL, NULL, \
                 ?6, ?7, ?8)",
            params![
                hold_id,
                capability_id,
                grant_index as i64,
                now,
                reserved_until_unix_secs,
                envelope.budget_total.map(|value| value as i64),
                envelope.delegation_depth as i64,
                envelope.root_budget_holder,
            ],
        )?;
        if inserted == 0 {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` already exists"
            )));
        }
        Ok(())
    }

    /// Project a single hold by id, including its reserved-until deadline.
    pub fn budget_hold_snapshot(
        &self,
        hold_id: &str,
    ) -> Result<Option<BudgetHoldSnapshot>, BudgetStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| BudgetStoreError::Invariant("budget store mutex poisoned".to_string()))?;
        connection
            .query_row(
                "SELECT hold_id, capability_id, grant_index, authorized_exposure_units, \
                 remaining_exposure_units, disposition, reserved_until, \
                 authority_id, lease_id, lease_epoch, reserved_currency, \
                 reserved_payment_reference, reserved_budget_total, \
                 reserved_delegation_depth, reserved_root_budget_holder \
                 FROM budget_authorization_holds WHERE hold_id = ?1",
                params![hold_id],
                |row| {
                    let disposition = row.get::<_, String>(5)?;
                    let disposition = HoldDisposition::parse(&disposition)
                        .map(|value| match value {
                            HoldDisposition::Open => BudgetHoldDispositionView::Open,
                            HoldDisposition::Released => BudgetHoldDispositionView::Released,
                            HoldDisposition::Reversed => BudgetHoldDispositionView::Reversed,
                            HoldDisposition::Reconciled => BudgetHoldDispositionView::Reconciled,
                            HoldDisposition::Expired => BudgetHoldDispositionView::Expired,
                        })
                        .ok_or_else(|| {
                            rusqlite::Error::FromSqlConversionFailure(
                                5,
                                rusqlite::types::Type::Text,
                                Box::new(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!("unknown hold disposition `{disposition}`"),
                                )),
                            )
                        })?;
                    let authority =
                        sqlite_budget_event_authority(row.get(7)?, row.get(8)?, row.get(9)?)?;
                    Ok(BudgetHoldSnapshot {
                        hold_id: row.get::<_, String>(0)?,
                        capability_id: row.get::<_, String>(1)?,
                        grant_index: row.get::<_, i64>(2)? as usize,
                        authorized_exposure_units: row.get::<_, i64>(3)? as u64,
                        remaining_exposure_units: row.get::<_, i64>(4)? as u64,
                        disposition,
                        reserved_until: row.get::<_, Option<i64>>(6)?,
                        reserved_currency: row.get::<_, Option<String>>(10)?,
                        reserved_payment_reference: row.get::<_, Option<String>>(11)?,
                        reserved_budget_total: row
                            .get::<_, Option<i64>>(12)?
                            .map(|value| value as u64),
                        reserved_delegation_depth: row
                            .get::<_, Option<i64>>(13)?
                            .map(|value| value as u32),
                        reserved_root_budget_holder: row.get::<_, Option<String>>(14)?,
                        authority,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Ids of holds still `open` that were stamped as delegated
    /// reserve-for-caller reservations: marked reserved (a non-NULL
    /// `reserved_until`) with a delegation depth of at least one. Such a hold
    /// keeps its delegated child's sibling-sum share admitted against the parent
    /// for as long as it stays open, so a freshly built mediation kernel drains
    /// exactly these holds before resuming delegated admission after a restart. A
    /// depth-zero or unstamped reserved hold carries no such share and is
    /// excluded, as is any non-open hold. Errors fail-closed rather than reporting
    /// a partial set, so the kernel aborts admission on a store read error.
    pub(super) fn list_open_delegated_reserved_holds(
        &self,
    ) -> Result<Vec<String>, BudgetStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| BudgetStoreError::Invariant("budget store mutex poisoned".to_string()))?;
        let mut statement = connection.prepare(
            "SELECT hold_id FROM budget_authorization_holds \
             WHERE disposition = 'open' AND reserved_until IS NOT NULL \
               AND reserved_delegation_depth IS NOT NULL AND reserved_delegation_depth >= 1",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut ids = Vec::new();
        for row in rows {
            ids.push(row?);
        }
        Ok(ids)
    }

    /// Whether any hold id begins with `budget-hold:{request_id}:`, regardless of
    /// disposition or the capability id and grant index encoded after it. The
    /// mediated pre-execution gate derives each hold id from
    /// (request_id, capability id, grant index), so a replay of one request_id
    /// under a different capability token must still be seen as taken. `request_id`
    /// is caller-supplied, so its LIKE metacharacters (`%`, `_`, and the escape
    /// char) are escaped and the pattern is bound with an explicit ESCAPE clause,
    /// so a request_id containing `%` or `_` can neither widen nor narrow the match
    /// onto another caller's reservation.
    pub(super) fn hold_exists_for_request_id(
        &self,
        request_id: &str,
    ) -> Result<bool, BudgetStoreError> {
        let prefix = format!("budget-hold:{request_id}:");
        let pattern = Self::sqlite_like_prefix_pattern(&prefix);
        let connection = self
            .connection
            .lock()
            .map_err(|_| BudgetStoreError::Invariant("budget store mutex poisoned".to_string()))?;
        Ok(connection
            .query_row(
                "SELECT 1 FROM budget_authorization_holds \
                 WHERE hold_id LIKE ?1 ESCAPE '\\' LIMIT 1",
                params![pattern],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Rows still `open`:
    /// `(hold_id, capability_id, grant_index, remaining_exposure_units, authority)`.
    /// A hold with inconsistent authority lease columns is rejected fail-closed.
    pub(super) fn list_open_holds(&self) -> Result<Vec<OpenHold>, BudgetStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| BudgetStoreError::Invariant("budget store mutex poisoned".to_string()))?;
        let mut statement = connection.prepare(
            "SELECT hold_id, capability_id, grant_index, remaining_exposure_units, \
             authority_id, lease_id, lease_epoch \
             FROM budget_authorization_holds WHERE disposition = 'open'",
        )?;
        let rows = statement.query_map([], |row| {
            let authority = sqlite_budget_event_authority(row.get(4)?, row.get(5)?, row.get(6)?)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? as u32,
                row.get::<_, i64>(3)? as u64,
                authority,
            ))
        })?;
        let mut holds = Vec::new();
        for row in rows {
            holds.push(row?);
        }
        Ok(holds)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_kernel::budget_store::{
        BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetStore,
    };
    use std::collections::HashMap;

    fn open_temp_store() -> SqliteBudgetStore {
        let dir = std::env::temp_dir().join(format!("chio-reaper-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        SqliteBudgetStore::open(dir.join("budget.sqlite")).unwrap()
    }

    fn authorize(store: &SqliteBudgetStore, hold_id: &str, cap: &str) {
        authorize_with_authority(store, hold_id, cap, None);
    }

    fn authorize_with_authority(
        store: &SqliteBudgetStore,
        hold_id: &str,
        cap: &str,
        authority: Option<BudgetEventAuthority>,
    ) {
        let decision = store
            .authorize_budget_hold(BudgetAuthorizeHoldRequest {
                capability_id: cap.to_string(),
                grant_index: 0,
                max_invocations: Some(10),
                requested_exposure_units: 100,
                max_cost_per_invocation: Some(100),
                max_total_cost_units: Some(1000),
                hold_id: Some(hold_id.to_string()),
                event_id: Some(format!("{hold_id}:authorize")),
                authority,
                payment_journal: None,
            })
            .unwrap();
        assert!(matches!(
            decision,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
    }

    #[test]
    fn ttl_reaper_settles_expired_unreconciled_reserved_holds_at_worst_case() {
        use chio_kernel::budget_store::{BudgetHoldDispositionView, BudgetReconcileHoldRequest};

        let store = open_temp_store();
        // Expired reserved hold.
        authorize(&store, "hold-expired", "cap-a");
        store
            .mark_hold_reserved_until(
                "hold-expired",
                100,
                "USD",
                None,
                &ReservedHoldEnvelope::default(),
            )
            .unwrap();
        // Not-yet-expired reserved hold.
        authorize(&store, "hold-fresh", "cap-b");
        store
            .mark_hold_reserved_until(
                "hold-fresh",
                5_000,
                "USD",
                None,
                &ReservedHoldEnvelope::default(),
            )
            .unwrap();
        // Reconciled reserved hold.
        authorize(&store, "hold-done", "cap-c");
        store
            .mark_hold_reserved_until(
                "hold-done",
                100,
                "USD",
                None,
                &ReservedHoldEnvelope::default(),
            )
            .unwrap();
        store
            .reconcile_budget_hold(BudgetReconcileHoldRequest {
                capability_id: "cap-c".to_string(),
                grant_index: 0,
                exposed_cost_units: 100,
                realized_spend_units: 40,
                hold_id: Some("hold-done".to_string()),
                event_id: Some("hold-done:reconcile".to_string()),
                authority: None,
            })
            .unwrap();

        let settled = store.reap_expired_reserved_holds(1_000).unwrap();
        assert_eq!(settled, 1, "only the expired reserved hold is settled");

        // cap-a expired reserved hold SETTLED at worst-case: the reserved amount is
        // forfeited to realized spend (committed stays 100), not released to 0.
        let cap_a = store.get_usage("cap-a", 0).unwrap().unwrap();
        assert_eq!(
            cap_a.total_cost_realized_spend, 100,
            "the forfeited worst-case becomes realized spend"
        );
        assert_eq!(
            cap_a.committed_cost_units().unwrap(),
            100,
            "the reserved worst-case stays consumed, the freed difference is gone"
        );
        // A second reap is idempotent: the settled hold is no longer open.
        assert_eq!(store.reap_expired_reserved_holds(1_000).unwrap(), 0);
        assert_eq!(
            store
                .budget_hold_snapshot("hold-expired")
                .unwrap()
                .unwrap()
                .disposition,
            BudgetHoldDispositionView::Reconciled
        );
        // cap-b not-yet-expired reserved hold untouched.
        assert_eq!(
            store
                .get_usage("cap-b", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            100
        );
        assert_eq!(
            store
                .budget_hold_snapshot("hold-fresh")
                .unwrap()
                .unwrap()
                .disposition,
            BudgetHoldDispositionView::Open
        );
        // cap-c reconciled hold untouched (realized 40).
        assert_eq!(
            store
                .get_usage("cap-c", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            40
        );
        assert_eq!(
            store
                .budget_hold_snapshot("hold-done")
                .unwrap()
                .unwrap()
                .disposition,
            BudgetHoldDispositionView::Reconciled
        );
    }

    #[test]
    fn budget_hold_snapshot_projects_reserved_hold() {
        use chio_kernel::budget_store::BudgetHoldDispositionView;

        let store = open_temp_store();
        authorize(&store, "hold-snap", "cap-snap");
        assert!(store
            .budget_hold_snapshot("hold-missing")
            .unwrap()
            .is_none());
        store
            .mark_hold_reserved_until(
                "hold-snap",
                4_242,
                "USD",
                Some("rail_txn_ref"),
                &ReservedHoldEnvelope {
                    budget_total: Some(1_000),
                    delegation_depth: 2,
                    root_budget_holder: "root-holder".to_string(),
                },
            )
            .unwrap();
        let snapshot = store.budget_hold_snapshot("hold-snap").unwrap().unwrap();
        assert_eq!(snapshot.capability_id, "cap-snap");
        assert_eq!(snapshot.remaining_exposure_units, 100);
        assert_eq!(snapshot.disposition, BudgetHoldDispositionView::Open);
        assert_eq!(snapshot.reserved_until, Some(4_242));
        assert_eq!(snapshot.reserved_currency.as_deref(), Some("USD"));
        assert_eq!(
            snapshot.reserved_payment_reference.as_deref(),
            Some("rail_txn_ref"),
            "a prepaid reservation records its rail transaction id durably"
        );
        assert_eq!(
            snapshot.reserved_budget_total,
            Some(1_000),
            "the grant ceiling is recorded durably on the reserved hold"
        );
        assert_eq!(snapshot.reserved_delegation_depth, Some(2));
        assert_eq!(
            snapshot.reserved_root_budget_holder.as_deref(),
            Some("root-holder"),
            "the delegation root is recorded durably on the reserved hold"
        );
    }

    #[test]
    fn mark_hold_reserved_on_missing_hold_fails_closed() {
        let store = open_temp_store();
        assert!(store
            .mark_hold_reserved_until("nope", 100, "USD", None, &ReservedHoldEnvelope::default())
            .is_err());
    }

    #[test]
    fn request_id_has_reserved_hold_matches_by_prefix_and_escapes_like_metacharacters() {
        let store = open_temp_store();
        // A reservation under capability A binds request_id `axc` to a hold whose
        // id embeds A. The reuse guard must report `axc` taken regardless of the
        // capability that opened it.
        authorize(&store, "budget-hold:axc:cap-a:0", "cap-a");

        assert_eq!(
            store.request_id_has_reserved_hold("axc").unwrap(),
            Some(true),
            "the request_id that backs the hold is reported taken"
        );
        assert_eq!(
            store.request_id_has_reserved_hold("other").unwrap(),
            Some(false),
            "a request_id with no hold is reported free"
        );
        // request_id is caller-supplied, so LIKE metacharacters in it must be
        // escaped: `_` (any single char) and `%` (any run) must not widen the
        // prefix onto the different stored request_id `axc`.
        assert_eq!(
            store.request_id_has_reserved_hold("a_c").unwrap(),
            Some(false),
            "an underscore in request_id must not match a different stored id"
        );
        assert_eq!(
            store.request_id_has_reserved_hold("a%c").unwrap(),
            Some(false),
            "a percent in request_id must not match a different stored id"
        );
    }

    #[test]
    fn reaper_reconciles_admitted_hold_and_reverses_orphan() {
        // SIGKILL after authorize commits but before reconcile. A naive
        // "release Open on restart" would enable double-spend; instead the
        // durable receipt log arbitrates.
        let store = open_temp_store();
        authorize(&store, "hold-admitted", "cap-a"); // durably admitted, realized 40
        authorize(&store, "hold-orphan", "cap-b"); // never admitted downstream
                                                   // Before reap both holds inflate committed_cost by their worst-case 100.
        assert_eq!(
            store
                .get_usage("cap-a", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            100
        );

        let mut realized = HashMap::new();
        realized.insert("hold-admitted".to_string(), 40u64);
        let summary = store.reap_holds_by_map(&realized).unwrap();
        assert_eq!(summary.reconciled, 1);
        assert_eq!(summary.reversed, 1);

        // cap-a reconciled down to realized 40; cap-b reversed back to 0.
        assert_eq!(
            store
                .get_usage("cap-a", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            40
        );
        assert_eq!(
            store
                .get_usage("cap-b", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            0
        );
    }

    #[test]
    fn reserve_invocation_hold_is_reversible_and_returns_the_invocation() {
        use chio_kernel::budget_store::{
            BudgetHoldDispositionView, BudgetReverseHoldRequest, BudgetStore,
        };

        let store = open_temp_store();
        // Debit the single invocation exactly as the reserve path does, then adopt
        // it into a durable zero-exposure reserved hold.
        assert!(store.try_increment("cap-inv", 0, Some(1)).unwrap());
        store
            .reserve_invocation_hold(
                "hold-inv",
                "cap-inv",
                0,
                4_242,
                &ReservedHoldEnvelope {
                    budget_total: None,
                    delegation_depth: 1,
                    root_budget_holder: "inv-root".to_string(),
                },
            )
            .unwrap();

        let snapshot = store.budget_hold_snapshot("hold-inv").unwrap().unwrap();
        assert_eq!(snapshot.authorized_exposure_units, 0);
        assert_eq!(snapshot.remaining_exposure_units, 0);
        assert_eq!(snapshot.disposition, BudgetHoldDispositionView::Open);
        assert_eq!(snapshot.reserved_until, Some(4_242));
        assert_eq!(
            snapshot.reserved_currency, None,
            "an invocation reservation records no currency"
        );
        assert_eq!(
            snapshot.reserved_budget_total, None,
            "an invocation reservation carries no monetary ceiling"
        );
        assert_eq!(snapshot.reserved_delegation_depth, Some(1));
        assert_eq!(
            snapshot.reserved_root_budget_holder.as_deref(),
            Some("inv-root"),
            "an invocation reservation still records its delegation root"
        );
        assert_eq!(
            store
                .get_usage("cap-inv", 0)
                .unwrap()
                .unwrap()
                .invocation_count,
            1
        );

        // Reversing the hold returns the invocation to the grant.
        store
            .reverse_budget_hold(BudgetReverseHoldRequest {
                capability_id: "cap-inv".to_string(),
                grant_index: 0,
                reversed_exposure_units: snapshot.remaining_exposure_units,
                hold_id: Some("hold-inv".to_string()),
                event_id: Some("hold-inv:reverse".to_string()),
                authority: snapshot.authority,
            })
            .unwrap();
        assert_eq!(
            store
                .get_usage("cap-inv", 0)
                .unwrap()
                .unwrap()
                .invocation_count,
            0,
            "reversing an invocation reservation returns the debited invocation"
        );
        assert_eq!(
            store
                .budget_hold_snapshot("hold-inv")
                .unwrap()
                .unwrap()
                .disposition,
            BudgetHoldDispositionView::Reversed
        );

        // A duplicate reserve under the same id fails closed.
        assert!(store
            .reserve_invocation_hold(
                "hold-inv",
                "cap-inv",
                0,
                9_000,
                &ReservedHoldEnvelope::default()
            )
            .is_err());
    }

    #[test]
    fn reaper_forfeits_expired_invocation_reserve_keeping_it_consumed() {
        use chio_kernel::budget_store::{BudgetHoldDispositionView, BudgetStore};

        let store = open_temp_store();
        assert!(store.try_increment("cap-inv", 0, Some(1)).unwrap());
        store
            .reserve_invocation_hold(
                "hold-inv",
                "cap-inv",
                0,
                100,
                &ReservedHoldEnvelope::default(),
            )
            .unwrap();

        let settled = store.reap_expired_reserved_holds(1_000).unwrap();
        assert_eq!(settled, 1, "the expired invocation reservation is settled");
        assert_eq!(
            store
                .get_usage("cap-inv", 0)
                .unwrap()
                .unwrap()
                .invocation_count,
            1,
            "reaping forfeits the invocation (stays consumed), matching monetary reap"
        );
        assert_eq!(
            store
                .budget_hold_snapshot("hold-inv")
                .unwrap()
                .unwrap()
                .disposition,
            BudgetHoldDispositionView::Reconciled
        );
        // Idempotent: a settled hold is no longer open.
        assert_eq!(store.reap_expired_reserved_holds(1_000).unwrap(), 0);
    }

    #[test]
    fn reaper_reclaims_kernel_authored_holds_bearing_authority() {
        // Kernel-authored holds carry a BudgetEventAuthority lease. A crash after
        // authorize leaves them open; the reaper must load and present each hold's
        // stored authority so the store's authority check passes and the orphaned
        // holds are reclaimed rather than left reserved indefinitely.
        let store = open_temp_store();
        let authority = BudgetEventAuthority {
            authority_id: "kernel-authority".to_string(),
            lease_id: "lease-1".to_string(),
            lease_epoch: 0,
        };
        authorize_with_authority(&store, "hold-admitted", "cap-a", Some(authority.clone()));
        authorize_with_authority(&store, "hold-orphan", "cap-b", Some(authority));

        let mut realized = HashMap::new();
        realized.insert("hold-admitted".to_string(), 40u64);
        let summary = store.reap_holds_by_map(&realized).unwrap();
        assert_eq!(summary.reconciled, 1);
        assert_eq!(summary.reversed, 1);

        // cap-a reconciled to realized 40; cap-b orphan reversed to 0.
        assert_eq!(
            store
                .get_usage("cap-a", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            40
        );
        assert_eq!(
            store
                .get_usage("cap-b", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            0
        );
    }

    #[test]
    fn list_open_delegated_reserved_hold_ids_enumerates_only_open_delegated_reserved() {
        use chio_kernel::budget_store::BudgetReconcileHoldRequest;

        let store = open_temp_store();

        // (a) Open delegated reserve-for-caller hold: reserved with delegation
        // depth one, so its child's sibling-sum share stays admitted against the
        // parent until it closes. The restart gate must drain exactly this hold.
        authorize(&store, "hold-a-delegated", "cap-a");
        store
            .mark_hold_reserved_until(
                "hold-a-delegated",
                4_242,
                "USD",
                None,
                &ReservedHoldEnvelope {
                    budget_total: None,
                    delegation_depth: 1,
                    root_budget_holder: "root-a".to_string(),
                },
            )
            .unwrap();

        // (b) Open reserved hold at delegation depth zero: reserved but not
        // delegated, so it holds no sibling-sum share and must be excluded.
        authorize(&store, "hold-b-nondelegated", "cap-b");
        store
            .mark_hold_reserved_until(
                "hold-b-nondelegated",
                4_242,
                "USD",
                None,
                &ReservedHoldEnvelope {
                    budget_total: None,
                    delegation_depth: 0,
                    root_budget_holder: "root-b".to_string(),
                },
            )
            .unwrap();

        // (c) Delegated hold that has since closed: reconciled, so no longer open
        // and no longer holds a share, and must be excluded.
        authorize(&store, "hold-c-closed", "cap-c");
        store
            .mark_hold_reserved_until(
                "hold-c-closed",
                4_242,
                "USD",
                None,
                &ReservedHoldEnvelope {
                    budget_total: None,
                    delegation_depth: 1,
                    root_budget_holder: "root-c".to_string(),
                },
            )
            .unwrap();
        store
            .reconcile_budget_hold(BudgetReconcileHoldRequest {
                capability_id: "cap-c".to_string(),
                grant_index: 0,
                exposed_cost_units: 100,
                realized_spend_units: 40,
                hold_id: Some("hold-c-closed".to_string()),
                event_id: Some("hold-c-closed:reconcile".to_string()),
                authority: None,
            })
            .unwrap();

        // Some(..) switches the kernel onto the precise restart gate; the set
        // enumerates only the open delegated reserved hold.
        let ids = store.list_open_delegated_reserved_hold_ids().unwrap();
        assert_eq!(ids, Some(vec!["hold-a-delegated".to_string()]));
    }
}
