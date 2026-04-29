#![cfg_attr(not(any(loom, chio_kernel_loom)), allow(dead_code))]

#[cfg(any(loom, chio_kernel_loom))]
use std::collections::{BTreeSet, VecDeque};

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
fn loom_budget_atomic_decrement() {
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
