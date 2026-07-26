#![cfg_attr(not(any(loom, chio_kernel_loom)), allow(dead_code))]

#[cfg(any(loom, chio_kernel_loom))]
use std::collections::{BTreeSet, VecDeque};

#[cfg(any(loom, chio_kernel_loom))]
use loom::cell::UnsafeCell;
#[cfg(any(loom, chio_kernel_loom))]
use loom::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
#[cfg(any(loom, chio_kernel_loom))]
use loom::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
#[cfg(any(loom, chio_kernel_loom))]
use loom::thread;

#[cfg(any(loom, chio_kernel_loom))]
fn lock_mutex<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    match lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(any(loom, chio_kernel_loom))]
fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(any(loom, chio_kernel_loom))]
fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(any(loom, chio_kernel_loom))]
fn join_ok(handle: thread::JoinHandle<()>) {
    assert!(handle.join().is_ok(), "loom thread should complete");
}

#[cfg(any(loom, chio_kernel_loom))]
#[derive(Debug)]
struct ModelSession {
    id: u64,
    generation: u64,
    terminal: AtomicBool,
}

#[cfg(any(loom, chio_kernel_loom))]
impl ModelSession {
    fn new(id: u64, generation: u64) -> Self {
        Self {
            id,
            generation,
            terminal: AtomicBool::new(false),
        }
    }
}

#[cfg(any(loom, chio_kernel_loom))]
#[test]
fn loom_session_create_lookup_terminal_same_id() {
    loom::model(|| {
        let table: Arc<RwLock<Option<Arc<ModelSession>>>> = Arc::new(RwLock::new(None));
        let allowed = Arc::new(AtomicUsize::new(0));
        let denied_after_terminal = Arc::new(AtomicUsize::new(0));

        let create_table = Arc::clone(&table);
        let create = thread::spawn(move || {
            let session = Arc::new(ModelSession::new(7, 1));
            *write_lock(&create_table) = Some(session);
        });

        let lookup_table = Arc::clone(&table);
        let lookup_allowed = Arc::clone(&allowed);
        let lookup_denied = Arc::clone(&denied_after_terminal);
        let lookup = thread::spawn(move || {
            let session = read_lock(&lookup_table).as_ref().cloned();
            if let Some(session) = session {
                assert_eq!(session.id, 7);
                assert_eq!(session.generation, 1);
                thread::yield_now();
                if session.terminal.load(Ordering::Acquire) {
                    lookup_denied.fetch_add(1, Ordering::AcqRel);
                } else {
                    lookup_allowed.fetch_add(1, Ordering::AcqRel);
                }
            }
        });

        let terminal_table = Arc::clone(&table);
        let terminal = thread::spawn(move || {
            let session = read_lock(&terminal_table).as_ref().cloned();
            if let Some(session) = session {
                session.terminal.store(true, Ordering::Release);
            }
        });

        join_ok(create);
        join_ok(lookup);
        join_ok(terminal);

        assert!(
            allowed.load(Ordering::Acquire) <= 1,
            "lookup should allow at most once"
        );
        assert!(
            denied_after_terminal.load(Ordering::Acquire) <= 1,
            "terminal lookup should deny at most once"
        );
    });
}

#[cfg(any(loom, chio_kernel_loom))]
#[test]
fn loom_parent_signs_receipt_while_child_spawns() {
    loom::model(|| {
        let log = Arc::new(Mutex::new(Vec::<&'static str>::new()));

        let parent_log = Arc::clone(&log);
        let parent = thread::spawn(move || {
            lock_mutex(&parent_log).push("parent");
        });

        let child_log = Arc::clone(&log);
        let child = thread::spawn(move || {
            for _ in 0..2 {
                let mut log = lock_mutex(&child_log);
                if log.contains(&"parent") {
                    log.push("child");
                    return;
                }
                drop(log);
                thread::yield_now();
            }
        });

        join_ok(parent);
        join_ok(child);

        let log = lock_mutex(&log);
        let parent_index = log.iter().position(|entry| *entry == "parent");
        let child_index = log.iter().position(|entry| *entry == "child");
        if let Some(child_index) = child_index {
            assert!(
                parent_index.is_some_and(|parent_index| parent_index < child_index),
                "child receipt must reference an already written parent"
            );
        }
    });
}

#[cfg(any(loom, chio_kernel_loom))]
#[test]
fn loom_revocation_race_eval() {
    loom::model(|| {
        #[derive(Default)]
        struct RevocationModel {
            revoked: bool,
            events: Vec<&'static str>,
        }

        let store = Arc::new(Mutex::new(RevocationModel::default()));

        let eval_a_store = Arc::clone(&store);
        let eval_a = thread::spawn(move || {
            let mut store = lock_mutex(&eval_a_store);
            if store.revoked {
                store.events.push("deny");
            } else {
                store.events.push("allow");
            }
        });

        let eval_b_store = Arc::clone(&store);
        let eval_b = thread::spawn(move || {
            let mut store = lock_mutex(&eval_b_store);
            if store.revoked {
                store.events.push("deny");
            } else {
                store.events.push("allow");
            }
        });

        let revoke_store = Arc::clone(&store);
        let revoke = thread::spawn(move || {
            let mut store = lock_mutex(&revoke_store);
            store.revoked = true;
            store.events.push("revoke");
        });

        join_ok(eval_a);
        join_ok(eval_b);
        join_ok(revoke);

        let store = lock_mutex(&store);
        let mut revoked_seen = false;
        for event in &store.events {
            if *event == "revoke" {
                revoked_seen = true;
                continue;
            }
            assert!(
                !(revoked_seen && *event == "allow"),
                "evaluation allowed after revocation was inserted"
            );
        }
    });
}

#[cfg(any(loom, chio_kernel_loom))]
#[test]
fn loom_receipt_channel_producer_drain() {
    loom::model(|| {
        #[derive(Debug)]
        struct BoundedReceiptQueue {
            queue: VecDeque<u8>,
            accepted: Vec<u8>,
            signed: Vec<u8>,
            backpressure_observed: bool,
        }

        impl BoundedReceiptQueue {
            fn try_send(&mut self, receipt_id: u8) -> bool {
                if self.queue.len() == 1 {
                    self.backpressure_observed = true;
                    return false;
                }
                self.queue.push_back(receipt_id);
                self.accepted.push(receipt_id);
                true
            }

            fn drain_one(&mut self) {
                if let Some(receipt_id) = self.queue.pop_front() {
                    self.signed.push(receipt_id);
                }
            }
        }

        let queue = Arc::new(Mutex::new(BoundedReceiptQueue {
            queue: VecDeque::from([0]),
            accepted: vec![0],
            signed: Vec::new(),
            backpressure_observed: false,
        }));
        let producer_attempted_full_send = Arc::new(AtomicBool::new(false));

        let producer_queue = Arc::clone(&queue);
        let producer_attempted = Arc::clone(&producer_attempted_full_send);
        let producer = thread::spawn(move || {
            {
                let mut queue = lock_mutex(&producer_queue);
                let accepted = queue.try_send(1);
                assert!(
                    !accepted,
                    "prefilled bounded queue should surface backpressure"
                );
            }
            producer_attempted.store(true, Ordering::Release);
            thread::yield_now();
            let mut queue = lock_mutex(&producer_queue);
            let _accepted_after_drain = queue.try_send(1);
        });

        let signer_queue = Arc::clone(&queue);
        let signer_attempted = Arc::clone(&producer_attempted_full_send);
        let signer = thread::spawn(move || {
            while !signer_attempted.load(Ordering::Acquire) {
                thread::yield_now();
            }
            lock_mutex(&signer_queue).drain_one();
            thread::yield_now();
            lock_mutex(&signer_queue).drain_one();
        });

        join_ok(producer);
        join_ok(signer);

        let mut queue = lock_mutex(&queue);
        while !queue.queue.is_empty() {
            queue.drain_one();
        }

        assert!(queue.backpressure_observed, "queue-full state was missed");
        let accepted: BTreeSet<u8> = queue.accepted.iter().copied().collect();
        let signed: BTreeSet<u8> = queue.signed.iter().copied().collect();
        assert_eq!(accepted, signed, "accepted receipt lost before signing");
        assert_eq!(queue.signed.len(), signed.len(), "receipt signed twice");
    });
}

#[cfg(any(loom, chio_kernel_loom))]
#[test]
fn loom_inflight_increment_decrement_storm() {
    loom::model(|| {
        #[derive(Debug)]
        struct InflightRegistry {
            active: Mutex<[bool; 2]>,
            count: AtomicU64,
            underflow: AtomicBool,
        }

        impl InflightRegistry {
            fn track(&self, slot: usize) {
                let mut active = lock_mutex(&self.active);
                if !active[slot] {
                    active[slot] = true;
                    self.count.fetch_add(1, Ordering::AcqRel);
                }
            }

            fn complete(&self, slot: usize) {
                let mut active = lock_mutex(&self.active);
                if !active[slot] {
                    return;
                }
                active[slot] = false;
                if self
                    .count
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                        current.checked_sub(1)
                    })
                    .is_err()
                {
                    self.underflow.store(true, Ordering::Release);
                }
            }
        }

        let registry = Arc::new(InflightRegistry {
            active: Mutex::new([false, false]),
            count: AtomicU64::new(0),
            underflow: AtomicBool::new(false),
        });

        let worker_a_registry = Arc::clone(&registry);
        let worker_a = thread::spawn(move || {
            worker_a_registry.track(0);
            thread::yield_now();
            worker_a_registry.complete(0);
        });

        let worker_b_registry = Arc::clone(&registry);
        let worker_b = thread::spawn(move || {
            worker_b_registry.track(1);
            thread::yield_now();
            worker_b_registry.complete(1);
        });

        let cancel_registry = Arc::clone(&registry);
        let cancel = thread::spawn(move || {
            cancel_registry.complete(0);
            thread::yield_now();
            cancel_registry.complete(1);
        });

        join_ok(worker_a);
        join_ok(worker_b);
        join_ok(cancel);

        assert_eq!(
            registry.count.load(Ordering::Acquire),
            0,
            "inflight counter must return to zero"
        );
        assert!(
            !registry.underflow.load(Ordering::Acquire),
            "inflight counter underflowed"
        );
    });
}

#[cfg(any(loom, chio_kernel_loom))]
#[test]
fn loom_dashmap_session_insert_remove_concurrent() {
    loom::model(|| {
        let shard: Arc<Mutex<Option<Arc<ModelSession>>>> = Arc::new(Mutex::new(None));
        let lookup_count = Arc::new(AtomicUsize::new(0));

        let insert_shard = Arc::clone(&shard);
        let insert = thread::spawn(move || {
            *lock_mutex(&insert_shard) = Some(Arc::new(ModelSession::new(11, 3)));
        });

        let remove_shard = Arc::clone(&shard);
        let remove = thread::spawn(move || {
            let _removed = lock_mutex(&remove_shard).take();
        });

        let lookup_shard = Arc::clone(&shard);
        let lookup_seen = Arc::clone(&lookup_count);
        let lookup = thread::spawn(move || {
            let session = lock_mutex(&lookup_shard).as_ref().cloned();
            if let Some(session) = session {
                assert_eq!(session.id, 11);
                assert_eq!(session.generation, 3);
                lookup_seen.fetch_add(1, Ordering::AcqRel);
            }
        });

        join_ok(insert);
        join_ok(remove);
        join_ok(lookup);

        assert!(
            lookup_count.load(Ordering::Acquire) <= 1,
            "lookup observed a torn duplicate session"
        );
    });
}

#[cfg(any(loom, chio_kernel_loom))]
#[test]
fn loom_emergency_stop_arcswap() {
    loom::model(|| {
        #[derive(Debug)]
        struct EmergencyStopModel {
            stopped: AtomicBool,
            reason: RwLock<Arc<Option<String>>>,
        }

        impl EmergencyStopModel {
            fn store_reason(&self, reason: Option<String>) {
                *write_lock(&self.reason) = Arc::new(reason);
            }

            fn load_reason_if_stopped(&self) -> Option<String> {
                if !self.stopped.load(Ordering::Acquire) {
                    return None;
                }
                read_lock(&self.reason).as_ref().clone()
            }
        }

        let stop = Arc::new(EmergencyStopModel {
            stopped: AtomicBool::new(false),
            reason: RwLock::new(Arc::new(None)),
        });

        let writer_stop = Arc::clone(&stop);
        let writer = thread::spawn(move || {
            writer_stop.store_reason(Some("operator stop".to_string()));
            thread::yield_now();
            writer_stop.stopped.store(true, Ordering::Release);
        });

        let reader_stop = Arc::clone(&stop);
        let reader = thread::spawn(move || {
            let observed = reader_stop.load_reason_if_stopped();
            assert!(
                observed
                    .as_ref()
                    .is_none_or(|reason| reason == "operator stop"),
                "reader observed a partial emergency stop reason"
            );
        });

        join_ok(writer);
        join_ok(reader);

        assert_eq!(
            stop.load_reason_if_stopped().as_deref(),
            Some("operator stop")
        );
    });
}

#[cfg(any(loom, chio_kernel_loom))]
#[test]
fn protocol_primitives_last_unit_contention() {
    loom::model(|| {
        #[derive(Debug)]
        struct TenantBudget {
            remaining: AtomicU64,
            depleted: AtomicUsize,
            allowed: AtomicUsize,
        }

        impl TenantBudget {
            fn charge_one(&self) {
                loop {
                    let current = self.remaining.load(Ordering::Acquire);
                    if current == 0 {
                        self.depleted.fetch_add(1, Ordering::AcqRel);
                        return;
                    }
                    if self
                        .remaining
                        .compare_exchange(current, current - 1, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        self.allowed.fetch_add(1, Ordering::AcqRel);
                        return;
                    }
                    thread::yield_now();
                }
            }
        }

        let budget = Arc::new(TenantBudget {
            remaining: AtomicU64::new(1),
            depleted: AtomicUsize::new(0),
            allowed: AtomicUsize::new(0),
        });

        let budget_a = Arc::clone(&budget);
        let a = thread::spawn(move || {
            budget_a.charge_one();
        });

        let budget_b = Arc::clone(&budget);
        let b = thread::spawn(move || {
            budget_b.charge_one();
        });

        join_ok(a);
        join_ok(b);

        assert_eq!(
            budget.allowed.load(Ordering::Acquire),
            1,
            "exactly one charge should be allowed"
        );
        assert_eq!(
            budget.depleted.load(Ordering::Acquire),
            1,
            "exactly one charge should observe depletion"
        );
        assert_eq!(
            budget.remaining.load(Ordering::Acquire),
            0,
            "budget must not go below zero"
        );
    });
}

#[cfg(any(loom, chio_kernel_loom))]
#[derive(Debug, Default)]
struct CompositeQuotaModel {
    reserved: [u8; 4],
}

#[cfg(any(loom, chio_kernel_loom))]
impl CompositeQuotaModel {
    fn authorize(&mut self, keys: [usize; 3]) -> bool {
        if keys.iter().any(|key| self.reserved[*key] >= 1) {
            return false;
        }
        for key in keys {
            self.reserved[key] += 1;
        }
        true
    }
}

#[cfg(any(loom, chio_kernel_loom))]
#[test]
fn protocol_primitives_three_key_all_or_nothing_admission() {
    loom::model(|| {
        let quotas = Arc::new(Mutex::new(CompositeQuotaModel::default()));
        let allowed_a = Arc::new(AtomicBool::new(false));
        let allowed_b = Arc::new(AtomicBool::new(false));

        let quotas_a = Arc::clone(&quotas);
        let result_a = Arc::clone(&allowed_a);
        let a = thread::spawn(move || {
            result_a.store(
                lock_mutex(&quotas_a).authorize([0, 1, 2]),
                Ordering::Release,
            );
        });

        let quotas_b = Arc::clone(&quotas);
        let result_b = Arc::clone(&allowed_b);
        let b = thread::spawn(move || {
            result_b.store(
                lock_mutex(&quotas_b).authorize([1, 2, 3]),
                Ordering::Release,
            );
        });

        join_ok(a);
        join_ok(b);

        assert_ne!(
            allowed_a.load(Ordering::Acquire),
            allowed_b.load(Ordering::Acquire),
            "exactly one overlapping composite hold must succeed"
        );
        let quotas = lock_mutex(&quotas);
        assert_eq!(quotas.reserved[1], 1, "shared quota must be reserved once");
        assert_eq!(quotas.reserved[2], 1, "shared quota must be reserved once");
        assert_eq!(
            quotas.reserved[0] + quotas.reserved[3],
            1,
            "the denied hold must not reserve its private quota"
        );
    });
}

#[cfg(any(loom, chio_kernel_loom))]
#[derive(Debug, Default)]
struct ImmutableMaximumModel {
    maximum: Option<u8>,
}

#[cfg(any(loom, chio_kernel_loom))]
impl ImmutableMaximumModel {
    fn define(&mut self, maximum: u8) -> bool {
        match self.maximum {
            Some(existing) => existing == maximum,
            None => {
                self.maximum = Some(maximum);
                true
            }
        }
    }
}

#[cfg(any(loom, chio_kernel_loom))]
#[test]
fn protocol_primitives_immutable_maximum_race() {
    loom::model(|| {
        let quota = Arc::new(Mutex::new(ImmutableMaximumModel::default()));
        let accepted = Arc::new(AtomicUsize::new(0));

        let quota_a = Arc::clone(&quota);
        let accepted_a = Arc::clone(&accepted);
        let a = thread::spawn(move || {
            if lock_mutex(&quota_a).define(1) {
                accepted_a.fetch_add(1, Ordering::AcqRel);
            }
        });

        let quota_b = Arc::clone(&quota);
        let accepted_b = Arc::clone(&accepted);
        let b = thread::spawn(move || {
            if lock_mutex(&quota_b).define(2) {
                accepted_b.fetch_add(1, Ordering::AcqRel);
            }
        });

        join_ok(a);
        join_ok(b);

        assert_eq!(accepted.load(Ordering::Acquire), 1);
        assert!(matches!(lock_mutex(&quota).maximum, Some(1 | 2)));
    });
}

#[cfg(any(loom, chio_kernel_loom))]
#[derive(Debug, Default)]
struct CumulativeApprovalModel {
    reserved_units: u64,
}

#[cfg(any(loom, chio_kernel_loom))]
impl CumulativeApprovalModel {
    fn reserve(&mut self, units: u64, threshold: u64) -> bool {
        let prospective = self.reserved_units + units;
        self.reserved_units = prospective;
        prospective < threshold
    }
}

#[cfg(any(loom, chio_kernel_loom))]
#[test]
fn loom_cumulative_approval_serializes_concurrent_threshold_crossing() {
    loom::model(|| {
        let account = Arc::new(Mutex::new(CumulativeApprovalModel::default()));
        let authorized = Arc::new(AtomicUsize::new(0));
        let approval_required = Arc::new(AtomicUsize::new(0));

        let spawn_reservation =
            |account: Arc<Mutex<CumulativeApprovalModel>>,
             authorized: Arc<AtomicUsize>,
             approval_required: Arc<AtomicUsize>| {
                thread::spawn(move || {
                    if lock_mutex(&account).reserve(60, 100) {
                        authorized.fetch_add(1, Ordering::AcqRel);
                    } else {
                        approval_required.fetch_add(1, Ordering::AcqRel);
                    }
                })
            };

        let a = spawn_reservation(
            Arc::clone(&account),
            Arc::clone(&authorized),
            Arc::clone(&approval_required),
        );
        let b = spawn_reservation(
            Arc::clone(&account),
            Arc::clone(&authorized),
            Arc::clone(&approval_required),
        );

        join_ok(a);
        join_ok(b);

        assert_eq!(authorized.load(Ordering::Acquire), 1);
        assert_eq!(approval_required.load(Ordering::Acquire), 1);
        assert_eq!(lock_mutex(&account).reserved_units, 120);
    });
}

#[cfg(any(loom, chio_kernel_loom))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReservationState {
    Authorized,
    Captured,
    Reversed,
}

#[cfg(any(loom, chio_kernel_loom))]
#[derive(Debug)]
struct ReservationTransitionModel {
    state: ReservationState,
    reserved: u8,
    captured: u8,
}

#[cfg(any(loom, chio_kernel_loom))]
impl ReservationTransitionModel {
    fn capture(&mut self) -> bool {
        if self.state != ReservationState::Authorized {
            return false;
        }
        self.reserved -= 1;
        self.captured += 1;
        self.state = ReservationState::Captured;
        true
    }

    fn reverse(&mut self) -> bool {
        if self.state != ReservationState::Authorized {
            return false;
        }
        self.reserved -= 1;
        self.state = ReservationState::Reversed;
        true
    }
}

#[cfg(any(loom, chio_kernel_loom))]
#[test]
fn protocol_primitives_capture_versus_reverse() {
    loom::model(|| {
        let reservation = Arc::new(Mutex::new(ReservationTransitionModel {
            state: ReservationState::Authorized,
            reserved: 1,
            captured: 0,
        }));
        let captured = Arc::new(AtomicBool::new(false));
        let reversed = Arc::new(AtomicBool::new(false));

        let capture_reservation = Arc::clone(&reservation);
        let capture_result = Arc::clone(&captured);
        let capture = thread::spawn(move || {
            capture_result.store(
                lock_mutex(&capture_reservation).capture(),
                Ordering::Release,
            );
        });

        let reverse_reservation = Arc::clone(&reservation);
        let reverse_result = Arc::clone(&reversed);
        let reverse = thread::spawn(move || {
            reverse_result.store(
                lock_mutex(&reverse_reservation).reverse(),
                Ordering::Release,
            );
        });

        join_ok(capture);
        join_ok(reverse);

        assert_ne!(
            captured.load(Ordering::Acquire),
            reversed.load(Ordering::Acquire)
        );
        let reservation = lock_mutex(&reservation);
        assert_eq!(reservation.reserved, 0);
        assert_eq!(
            reservation.captured,
            u8::from(reservation.state == ReservationState::Captured)
        );
    });
}

#[cfg(any(loom, chio_kernel_loom))]
#[test]
fn protocol_primitives_idempotent_compensation() {
    loom::model(|| {
        let reservation = Arc::new(Mutex::new(ReservationTransitionModel {
            state: ReservationState::Authorized,
            reserved: 1,
            captured: 0,
        }));
        let applied = Arc::new(AtomicUsize::new(0));

        let reservation_a = Arc::clone(&reservation);
        let applied_a = Arc::clone(&applied);
        let a = thread::spawn(move || {
            if lock_mutex(&reservation_a).reverse() {
                applied_a.fetch_add(1, Ordering::AcqRel);
            }
        });

        let reservation_b = Arc::clone(&reservation);
        let applied_b = Arc::clone(&applied);
        let b = thread::spawn(move || {
            if lock_mutex(&reservation_b).reverse() {
                applied_b.fetch_add(1, Ordering::AcqRel);
            }
        });

        join_ok(a);
        join_ok(b);

        let reservation = lock_mutex(&reservation);
        assert_eq!(applied.load(Ordering::Acquire), 1);
        assert_eq!(reservation.state, ReservationState::Reversed);
        assert_eq!(reservation.reserved, 0);
        assert_eq!(reservation.captured, 0);
    });
}

#[cfg(any(loom, chio_kernel_loom))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalState {
    Pending,
    Authorized,
    Reversed,
}

#[cfg(any(loom, chio_kernel_loom))]
fn transition_pending_approval(state: &mut ApprovalState, target: ApprovalState) -> bool {
    if *state != ApprovalState::Pending {
        return false;
    }
    *state = target;
    true
}

#[cfg(any(loom, chio_kernel_loom))]
#[test]
fn loom_approval_attachment_and_pending_reverse_have_one_winner() {
    loom::model(|| {
        let state = Arc::new(Mutex::new(ApprovalState::Pending));
        let attached = Arc::new(AtomicBool::new(false));
        let reversed = Arc::new(AtomicBool::new(false));

        let attach_state = Arc::clone(&state);
        let attach_result = Arc::clone(&attached);
        let attach = thread::spawn(move || {
            attach_result.store(
                transition_pending_approval(
                    &mut lock_mutex(&attach_state),
                    ApprovalState::Authorized,
                ),
                Ordering::Release,
            );
        });

        let reverse_state = Arc::clone(&state);
        let reverse_result = Arc::clone(&reversed);
        let reverse = thread::spawn(move || {
            reverse_result.store(
                transition_pending_approval(
                    &mut lock_mutex(&reverse_state),
                    ApprovalState::Reversed,
                ),
                Ordering::Release,
            );
        });

        join_ok(attach);
        join_ok(reverse);

        assert_ne!(
            attached.load(Ordering::Acquire),
            reversed.load(Ordering::Acquire)
        );
        assert_ne!(*lock_mutex(&state), ApprovalState::Pending);
    });
}

#[cfg(any(loom, chio_kernel_loom))]
#[derive(Debug)]
struct ModelDropGuard {
    armed: bool,
    dispatch_started: bool,
    receipt_id: u8,
}

#[cfg(any(loom, chio_kernel_loom))]
/// Models the kernel's receipt store (see
/// chio-kernel/src/kernel/responses/receipt_persistence.rs::record_chio_receipt
/// and dispatch.rs::record_child_receipt) as a non-atomic check-then-write:
/// snapshot the next free slot, yield (so loom can schedule a competing
/// append between the read and the write), then write the receipt into
/// that slot and publish the new length. A single call is race-free only
/// because the caller holds `receipt_store_write_lock` (a bare
/// `Mutex<()>`, matching the kernel's `receipt_store_write_lock` field)
/// for the whole call, exactly as the kernel serializes
/// `append_chio_receipt_returning_seq` / `append_child_receipt_returning_seq`
/// under that lock. If a future edit moved the append outside the lock,
/// or split its critical section, two concurrent appends could snapshot
/// the same slot and one receipt would silently overwrite (lose) the
/// other.
struct NonAtomicReceiptStore {
    len: UnsafeCell<usize>,
    slots: UnsafeCell<[u8; 2]>,
}

#[cfg(any(loom, chio_kernel_loom))]
impl NonAtomicReceiptStore {
    fn new() -> Self {
        Self {
            len: UnsafeCell::new(0),
            slots: UnsafeCell::new([0; 2]),
        }
    }

    /// Appends `receipt_id`. Callers must hold the paired
    /// `receipt_store_write_lock` for the duration of this call; the
    /// read-modify-write below is not atomic on its own.
    fn append(&self, receipt_id: u8) {
        // Step 1: snapshot the next free slot (the check).
        let idx = self.len.with(|len| unsafe { *len });
        // Step 2: yield so loom explores schedules where a competing
        // append runs between the snapshot and the write-back below.
        thread::yield_now();
        // Step 3: write the receipt into the snapshotted slot and
        // publish the new length (the write). Two racing appends that
        // both snapshotted the same idx both land here; the later write
        // wins and the earlier receipt is lost.
        self.slots
            .with_mut(|slots| unsafe { (*slots)[idx] = receipt_id });
        self.len.with_mut(|len| unsafe { *len = idx + 1 });
    }

    fn snapshot(&self) -> Vec<u8> {
        let len = self.len.with(|len| unsafe { *len });
        let slots = self.slots.with(|slots| unsafe { *slots });
        slots[..len].to_vec()
    }
}

#[cfg(any(loom, chio_kernel_loom))]
impl ModelDropGuard {
    /// Models PostAdmissionDropGuard::drop: disarmed guards do
    /// nothing; pre-dispatch drops release reservations and write no
    /// receipt; post-dispatch drops retain reservations and append exactly
    /// one receipt while holding the store write lock (models the
    /// kernel's receipt_store_write_lock std::sync::Mutex guarding the
    /// non-atomic receipt store append).
    fn run_drop(
        &self,
        receipt_store_write_lock: &Mutex<()>,
        receipt_store: &NonAtomicReceiptStore,
        released_reservations: &AtomicUsize,
    ) {
        if !self.armed {
            return;
        }
        if !self.dispatch_started {
            released_reservations.fetch_add(1, Ordering::AcqRel);
            return;
        }
        let _write_lock = lock_mutex(receipt_store_write_lock);
        receipt_store.append(self.receipt_id);
    }
}

#[cfg(any(loom, chio_kernel_loom))]
#[test]
fn loom_post_admission_drop_guards_race_on_receipt_store_write_lock() {
    loom::model(|| {
        let receipt_store_write_lock: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
        let receipt_store = Arc::new(NonAtomicReceiptStore::new());
        let released = Arc::new(AtomicUsize::new(0));

        let lock_a = Arc::clone(&receipt_store_write_lock);
        let store_a = Arc::clone(&receipt_store);
        let released_a = Arc::clone(&released);
        let guard_a = thread::spawn(move || {
            ModelDropGuard {
                armed: true,
                dispatch_started: true,
                receipt_id: 1,
            }
            .run_drop(&lock_a, &store_a, &released_a);
        });

        let lock_b = Arc::clone(&receipt_store_write_lock);
        let store_b = Arc::clone(&receipt_store);
        let released_b = Arc::clone(&released);
        let guard_b = thread::spawn(move || {
            ModelDropGuard {
                armed: true,
                dispatch_started: true,
                receipt_id: 2,
            }
            .run_drop(&lock_b, &store_b, &released_b);
        });

        join_ok(guard_a);
        join_ok(guard_b);

        let receipts = receipt_store.snapshot();
        let ids: BTreeSet<u8> = receipts.iter().copied().collect();
        assert_eq!(receipts.len(), 2, "a concurrent drop lost a receipt");
        assert_eq!(
            ids,
            BTreeSet::from([1, 2]),
            "each dropped call must record its own receipt exactly once"
        );
        assert_eq!(
            released.load(Ordering::Acquire),
            0,
            "post-dispatch drops must never release reservations"
        );
    });
}

#[cfg(any(loom, chio_kernel_loom))]
#[test]
fn loom_disarmed_drop_guard_is_noop() {
    loom::model(|| {
        let receipt_store_write_lock: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
        let receipt_store = Arc::new(NonAtomicReceiptStore::new());
        let released = Arc::new(AtomicUsize::new(0));

        let lock = Arc::clone(&receipt_store_write_lock);
        let store = Arc::clone(&receipt_store);
        let released_worker = Arc::clone(&released);
        let worker = thread::spawn(move || {
            // Happy path: the dispatch await returned, so the evaluation
            // calls disarm() before dropping the guard.
            let mut guard = ModelDropGuard {
                armed: true,
                dispatch_started: true,
                receipt_id: 9,
            };
            guard.armed = false;
            guard.run_drop(&lock, &store, &released_worker);
        });

        join_ok(worker);

        assert!(
            receipt_store.snapshot().is_empty(),
            "a disarmed guard must not record a receipt"
        );
        assert_eq!(
            released.load(Ordering::Acquire),
            0,
            "a disarmed guard must not release reservations"
        );
    });
}

// Writer-liveness verdict publish/read. The production cell is an
// `ArcSwap<ReceiptWriterLiveness>` with a single publisher (the watchdog task)
// and many lock-free readers (every evaluate call). ArcSwap's internals are not
// loom-visible, so the publish/read is modeled here as an atomic verdict.
// Encoding: 0=Unknown, 1=Healthy, 2=Wedged. Proves the reader never observes a
// non-published (torn) value and that the last publish wins.
#[cfg(any(loom, chio_kernel_loom))]
#[test]
fn receipt_writer_liveness_no_lost_wakeup() {
    loom::model(|| {
        let cell = Arc::new(AtomicUsize::new(0));
        let publisher_cell = Arc::clone(&cell);
        let publisher = thread::spawn(move || {
            publisher_cell.store(1, Ordering::SeqCst);
            publisher_cell.store(2, Ordering::SeqCst);
        });
        let reader_cell = Arc::clone(&cell);
        let reader = thread::spawn(move || {
            let observed = reader_cell.load(Ordering::SeqCst);
            assert!(observed <= 2, "verdict must be a published value");
        });
        join_ok(publisher);
        join_ok(reader);
        assert_eq!(cell.load(Ordering::SeqCst), 2, "last publish must win");
    });
}
