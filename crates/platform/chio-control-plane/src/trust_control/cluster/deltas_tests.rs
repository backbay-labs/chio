use super::*;

#[cfg(test)]
mod capability_revocation_lag_tests {
    use super::observe_capability_revocation_lag;

    fn lag_count() -> u64 {
        let mut rendered = String::new();
        chio_metrics_spec::runtime::families::CAPABILITY_REVOCATION_LAG.render(&mut rendered);
        rendered
            .lines()
            .find(|line| {
                line.starts_with(
                    "chio_capability_revocation_lag_seconds_count{authority=\"control_plane\"}",
                )
            })
            .and_then(|line| line.rsplit(' ').next())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
    }

    /// A capability revoke path observes the capability-revocation lag family, so
    /// a backdated (propagated) revoke advances the SLO histogram.
    #[test]
    fn capability_revoke_observes_revocation_lag() {
        let before = lag_count();
        // Backdate the revoke instant by 45 seconds relative to now.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or(0);
        observe_capability_revocation_lag(now.saturating_sub(45));
        assert!(
            lag_count() > before,
            "a capability revoke must observe a capability-revocation lag sample"
        );
    }
}

#[cfg(test)]
mod deltas_tests {
    use super::*;
    use chio_test_support::prelude::*;
    use std::time::Duration;

    #[test]
    fn peer_round_stops_visiting_when_shutdown_fires_midround() {
        // A stop signal that lands while a sync round is partway through its peers
        // must halt the round at the current peer rather than dialing every
        // remaining peer (each up to CONTROL_HTTP_TIMEOUT) before the loop can
        // observe shutdown and exit.
        let (tx, rx) = tokio::sync::watch::channel(false);
        let peers = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
        ];
        let mut visited = Vec::new();
        visit_peers_until_shutdown(&peers, &rx, |peer_url| {
            visited.push(peer_url.to_string());
            if visited.len() == 2 {
                let _ = tx.send(true);
            }
        });
        assert_eq!(
            visited,
            vec!["a".to_string(), "b".to_string()],
            "the round must stop at the peer where shutdown fired, not finish the peer list"
        );
    }

    #[test]
    fn budget_pull_is_prioritized_first() {
        // Budget replication is pulled FIRST so a receipt/lineage backlog cannot
        // spend the shared round budget and starve the quorum-critical budget pull.
        assert_eq!(
            peer_pullers()[0] as usize,
            sync_peer_budgets as Puller as usize,
            "the budget pull must run first in the per-peer pull order"
        );
    }

    #[test]
    fn revocations_are_not_in_the_shared_budget_round() {
        // Revocations must replicate on their OWN round budget in sync_peer, NOT
        // share the budget/receipt round. If they were in this shared list a
        // sustained budget backlog (shared-round exhaustion) or a broken budget
        // endpoint could starve security-critical revocation propagation. Budget
        // stays first here.
        let shared = peer_pullers();
        assert_eq!(
            shared[0] as usize, sync_peer_budgets as Puller as usize,
            "budget remains first in the shared round"
        );
        assert!(
            !shared
                .iter()
                .any(|puller| *puller as usize == sync_peer_revocations as Puller as usize),
            "revocations must be pulled on an independent round budget, not the shared one"
        );
    }

    #[test]
    fn quorum_commit_timeout_covers_full_per_peer_sync_and_is_bounded() {
        // The wait must outlast a FULL serial sync_peer visit for every peer
        // preceding the quorum peer, not just one CONTROL_HTTP_TIMEOUT per peer. A
        // full visit is the three fixed blocking stages plus the two
        // wall-clock-bounded delta rounds.
        let interval = Duration::from_millis(25);
        let per_peer_sync =
            CONTROL_HTTP_TIMEOUT * 3 + PEER_ROUND_WALL_CLOCK_BUDGET + PEER_ROUND_WALL_CLOCK_BUDGET;

        assert!(budget_write_quorum_commit_timeout(interval, 0) >= Duration::from_secs(5));

        // One preceding peer must be budgeted a full sync_peer visit. A bound of one
        // CONTROL_HTTP_TIMEOUT per peer would give only 30s here, far short of it.
        let one = budget_write_quorum_commit_timeout(interval, 1);
        assert!(
            one >= per_peer_sync,
            "one preceding peer must allow a full serial sync_peer visit, got {one:?}"
        );

        // Still bounded by a fixed ceiling so a misconfigured huge peer list cannot
        // make the wait unbounded.
        assert!(budget_write_quorum_commit_timeout(interval, 10_000) <= Duration::from_secs(300));
    }

    fn storm_event(seq: u64, invocation_count_after: u32) -> BudgetMutationEventView {
        BudgetMutationEventView {
            event_id: format!("evt-{seq}"),
            hold_id: None,
            capability_id: "cap-page".to_string(),
            grant_index: 0,
            kind: "authorize_exposure".to_string(),
            allowed: Some(true),
            lifecycle: BudgetMutationLifecycleView::default(),
            recorded_at: seq as i64,
            event_seq: seq,
            usage_seq: Some(seq),
            exposure_units: 1,
            realized_spend_units: 0,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            invocation_count_after,
            total_cost_exposed_after: u64::from(invocation_count_after),
            total_cost_realized_spend_after: 0,
            authority: Some(BudgetMutationAuthorityView {
                authority_id: "http://origin-page".to_string(),
                lease_id: "http://origin-page#term-1".to_string(),
                lease_epoch: 1,
            }),
        }
    }

    fn temp_budget_db(tag: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("chio-{tag}-{nonce}.sqlite3"))
    }

    #[test]
    fn paginated_budget_delta_projects_last_included_event_not_current_head() {
        let db = temp_budget_db("event-time-budget-page");
        let store = SqliteBudgetStore::open(&db).test_unwrap();
        assert!(store
            .try_charge_cost_with_ids(
                "cap-page",
                0,
                None,
                10,
                Some(10),
                Some(100),
                Some("hold-1"),
                Some("hold-1:authorize"),
            )
            .test_unwrap());
        assert!(store
            .try_charge_cost_with_ids(
                "cap-page",
                0,
                None,
                10,
                Some(10),
                Some(100),
                Some("hold-2"),
                Some("hold-2:authorize"),
            )
            .test_unwrap());

        let page = collect_budget_mutation_event_views_after_seq(&store, 0, 1).test_unwrap();
        assert_eq!(page.len(), 1);
        let records = collect_budget_projection_views_for_events(&store, &page).test_unwrap();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        let event = &page[0];
        let current = store
            .get_usage("cap-page", 0)
            .test_unwrap()
            .test_expect("current usage");

        assert_eq!(record.seq, event.usage_seq);
        assert_eq!(record.invocation_count, event.invocation_count_after);
        assert_eq!(record.total_cost_exposed, event.total_cost_exposed_after);
        assert_eq!(
            record.total_cost_realized_spend,
            event.total_cost_realized_spend_after
        );
        assert!(current.seq > record.seq.test_expect("page usage sequence"));
        assert!(current.invocation_count > record.invocation_count);
        assert!(current.total_cost_exposed > record.total_cost_exposed);

        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn capture_only_budget_delta_uses_referenced_usage_timestamp() {
        let db = temp_budget_db("capture-usage-timestamp");
        let store = SqliteBudgetStore::open(&db).test_unwrap();
        assert!(store
            .try_charge_cost_with_ids(
                "cap-capture-time",
                0,
                None,
                10,
                Some(10),
                Some(100),
                Some("hold-capture-time"),
                Some("hold-capture-time:authorize"),
            )
            .test_unwrap());
        let authorized_usage = store
            .get_usage("cap-capture-time", 0)
            .test_unwrap()
            .test_expect("authorized usage");
        let authorization_event = store
            .mutation_event_for_event_id("hold-capture-time:authorize")
            .test_unwrap()
            .test_expect("authorization event");

        std::thread::sleep(Duration::from_millis(1_100));
        assert!(matches!(
            store
                .capture_invocation_reservations(BudgetCaptureInvocationRequest {
                    capability_id: "cap-capture-time".to_string(),
                    grant_index: 0,
                    hold_id: "hold-capture-time".to_string(),
                    event_id: "hold-capture-time:capture".to_string(),
                    trusted_time: None,
                    authority: None,
                })
                .test_unwrap(),
            BudgetInvocationCaptureDecision::Captured(_)
        ));

        let page =
            collect_budget_mutation_event_views_after_seq(&store, authorization_event.event_seq, 1)
                .test_unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].event_id, "hold-capture-time:capture");
        assert_eq!(page[0].usage_seq, Some(authorized_usage.seq));
        assert!(page[0].recorded_at > authorized_usage.updated_at);

        let records = collect_budget_projection_views_for_events(&store, &page).test_unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].seq, Some(authorized_usage.seq));
        assert_eq!(records[0].updated_at, authorized_usage.updated_at);
        assert_ne!(records[0].updated_at, page[0].recorded_at);

        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn oversized_budget_page_retries_smaller_before_snapshotting() {
        // A page can exceed BUDGET_DELTA_MAX_RECORDS just because we asked for a full
        // MAX_LIST_LIMIT window (events + their usages + abandoned seqs). Such a
        // large-but-PAGEABLE window must be delivered incrementally via a SMALLER
        // event limit, not routed straight to a full snapshot: the drain refetches
        // the SAME cursor with a smaller limit and imports the window (still
        // contiguity-checked, so no skip / no over-count).
        let db = temp_budget_db("retry-smaller-budget-page");
        let store = SqliteBudgetStore::open(&db).test_unwrap();

        // The oversized first page: MAX_LIST_LIMIT events plus a dense abandoned burst,
        // so record_count > BUDGET_DELTA_MAX_RECORDS. It carries MANY events, so it is
        // reducible: a smaller event window would fit under the cap.
        let over_cap = || BudgetDeltaResponse {
            records: Vec::new(),
            mutation_events: (1..=MAX_LIST_LIMIT as u64)
                .map(|seq| storm_event(seq, u32::try_from(seq).test_unwrap()))
                .chain(std::iter::once(storm_event(
                    BUDGET_DELTA_MAX_RECORDS as u64 + 2,
                    u32::try_from(MAX_LIST_LIMIT + 1).test_unwrap(),
                )))
                .collect(),
            abandoned_seqs: ((MAX_LIST_LIMIT as u64 + 1)..=(BUDGET_DELTA_MAX_RECORDS as u64 + 1))
                .collect(),
        };
        // The smaller retry page: a short contiguous run that imports cleanly.
        let small = || BudgetDeltaResponse {
            records: Vec::new(),
            mutation_events: (1..=3)
                .map(|seq| storm_event(seq, u32::try_from(seq).test_unwrap()))
                .collect(),
            abandoned_seqs: Vec::new(),
        };

        let calls = std::cell::RefCell::new(Vec::<(Option<u64>, usize)>::new());
        let result = drain_budget_delta_pages(
            &store,
            &mut PullRoundBudget::new(),
            None,
            |after_seq, limit| {
                calls.borrow_mut().push((after_seq, limit));
                Ok(match (after_seq, limit) {
                    // First fetch: full limit from the head -> the oversized window.
                    (None, l) if l >= MAX_LIST_LIMIT => over_cap(),
                    // Retry from the SAME head at a reduced limit -> the pageable window.
                    (None, _) => small(),
                    // Cursor advanced past the imported window -> the stream is drained.
                    _ => BudgetDeltaResponse {
                        records: Vec::new(),
                        mutation_events: Vec::new(),
                        abandoned_seqs: Vec::new(),
                    },
                })
            },
            |_cursor| {},
        );

        // The window drained incrementally; no ForceSnapshot escaped the drain.
        let applied = match result {
            Ok(applied) => applied,
            Err(other) => {
                panic!("a large-but-pageable window must drain, not force-snapshot: {other:?}")
            }
        };
        assert_eq!(applied, 3, "the smaller page's events were imported");
        // The drain retried the same cursor with a limit strictly below
        // MAX_LIST_LIMIT before ever force-snapshotting.
        let calls = calls.into_inner();
        assert!(
            calls
                .iter()
                .any(|(after, limit)| after.is_none() && *limit < MAX_LIST_LIMIT),
            "the drain must retry the SAME cursor with a smaller event limit before snapshotting, got {calls:?}"
        );
        // The follower actually holds the imported events (contiguity preserved).
        assert_eq!(store.max_mutation_event_seq().test_unwrap(), 3);

        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn unpageable_single_event_budget_page_still_force_snapshots() {
        // A GENUINELY unpageable window - a single live event preceded by a dense
        // rollback burst of abandoned seqs that alone exceeds the record cap -
        // cannot be split smaller, so the drain must still route the peer to full
        // snapshot recovery (ForceSnapshot) rather than shrink-looping forever.
        let db = temp_budget_db("unpageable-budget-page");
        let store = SqliteBudgetStore::open(&db).test_unwrap();

        let fetches = std::cell::RefCell::new(0usize);
        let result = drain_budget_delta_pages(
            &store,
            &mut PullRoundBudget::new(),
            None,
            |_after_seq, _limit| {
                *fetches.borrow_mut() += 1;
                Ok(BudgetDeltaResponse {
                    records: Vec::new(),
                    // ONE event; the abandoned burst ALONE exceeds the record cap, so
                    // no smaller event page can bring the count under the cap.
                    mutation_events: vec![storm_event(BUDGET_DELTA_MAX_RECORDS as u64 + 2, 1)],
                    abandoned_seqs: (1..=(BUDGET_DELTA_MAX_RECORDS as u64 + 1)).collect(),
                })
            },
            |_cursor| {},
        );

        match result {
            Err(PullError::ForceSnapshot(_)) => {}
            other => {
                panic!("a minimal one-event over-cap page must force-snapshot, got {other:?}")
            }
        }
        // A single-event page is not reducible, so it force-snapshots after exactly
        // ONE fetch: no unbounded shrink-retry loop.
        assert_eq!(
            fetches.into_inner(),
            1,
            "no shrink-retry for an unpageable single-event page"
        );

        let _ = std::fs::remove_file(&db);
    }
}
