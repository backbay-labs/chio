#![cfg_attr(not(loom), allow(dead_code))]

#[cfg(loom)]
use loom::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
#[cfg(loom)]
use loom::thread;

#[cfg(loom)]
fn lock_mutex<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    match lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(loom)]
fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(loom)]
fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(loom)]
fn join_ok(handle: thread::JoinHandle<()>) {
    assert!(handle.join().is_ok(), "loom thread should complete");
}

#[cfg(loom)]
#[derive(Debug)]
struct ModelLoadedModule {
    epoch: u64,
    instance_pre_cache: Mutex<Option<u64>>,
}

#[cfg(loom)]
impl ModelLoadedModule {
    fn new(epoch: u64) -> Self {
        Self {
            epoch,
            instance_pre_cache: Mutex::new(Some(epoch)),
        }
    }

    fn checkout(&self, checkouts: &Mutex<Vec<(u64, u64)>>) {
        let cache_epoch = {
            let mut cache = lock_mutex(&self.instance_pre_cache);
            match *cache {
                Some(cache_epoch) => cache_epoch,
                None => {
                    *cache = Some(self.epoch);
                    self.epoch
                }
            }
        };
        lock_mutex(checkouts).push((self.epoch, cache_epoch));
    }

    fn clear_instance_pre_cache(&self) {
        *lock_mutex(&self.instance_pre_cache) = None;
    }
}

#[cfg(loom)]
#[test]
fn loom_instance_pre_reload_vs_checkout() {
    loom::model(|| {
        let slot = Arc::new(RwLock::new(Arc::new(ModelLoadedModule::new(0))));
        let checkouts = Arc::new(Mutex::new(Vec::<(u64, u64)>::new()));

        let checkout_before_slot = Arc::clone(&slot);
        let checkout_before_log = Arc::clone(&checkouts);
        let checkout_before = thread::spawn(move || {
            let loaded = Arc::clone(&read_lock(&checkout_before_slot));
            thread::yield_now();
            loaded.checkout(&checkout_before_log);
        });

        let reload_slot = Arc::clone(&slot);
        let reload = thread::spawn(move || {
            let previous = {
                let mut slot = write_lock(&reload_slot);
                let previous = Arc::clone(&slot);
                *slot = Arc::new(ModelLoadedModule::new(1));
                previous
            };
            thread::yield_now();
            previous.clear_instance_pre_cache();
        });

        let checkout_after_slot = Arc::clone(&slot);
        let checkout_after_log = Arc::clone(&checkouts);
        let checkout_after = thread::spawn(move || {
            thread::yield_now();
            let loaded = Arc::clone(&read_lock(&checkout_after_slot));
            loaded.checkout(&checkout_after_log);
        });

        join_ok(checkout_before);
        join_ok(reload);
        join_ok(checkout_after);

        let checkouts = lock_mutex(&checkouts);
        for (module_epoch, cache_epoch) in checkouts.iter() {
            assert_eq!(
                module_epoch, cache_epoch,
                "checkout must use an InstancePre cache matching its loaded module epoch"
            );
        }
    });
}
