use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

use crate::SizeGauge;

struct Timestamped<V> {
    value: V,
    last_seen_secs: u64,
    /// Sequence number of this key's newest insert. `order` entries carry the
    /// seq they were pushed with, so a stale duplicate left behind by a
    /// re-insert is distinguishable from the key's live position.
    seq: u64,
}

/// Capacity-bounded, optionally TTL-swept map for caches and rate-limit tables.
/// Eviction order is oldest-insert (approximate LRU: a re-insert of an existing
/// key moves it to newest; `get` refreshes the idle timestamp but does not
/// reorder). `insert` returns any (key, value) evicted for capacity so the
/// caller can persist-before-drop. `capacity == 0` disables the cache,
/// mirroring `Ring`.
pub struct BoundedMap<K, V> {
    inner: HashMap<K, Timestamped<V>>,
    order: VecDeque<(K, u64)>,
    capacity: usize,
    idle_ttl_secs: u64,
    sweep_interval: usize,
    inserts_since_sweep: usize,
    next_seq: u64,
    gauge: SizeGauge,
}

impl<K: Eq + Hash + Clone, V> BoundedMap<K, V> {
    pub fn new(capacity: usize, idle_ttl_secs: u64, gauge: SizeGauge) -> Self {
        Self {
            inner: HashMap::new(),
            order: VecDeque::new(),
            capacity,
            idle_ttl_secs,
            sweep_interval: 256,
            inserts_since_sweep: 0,
            next_seq: 0,
            gauge,
        }
    }

    pub fn insert(&mut self, key: K, value: V, now_secs: u64) -> Option<(K, V)> {
        if self.capacity == 0 {
            return Some((key, value));
        }
        self.inserts_since_sweep = self.inserts_since_sweep.saturating_add(1);
        if self.inserts_since_sweep >= self.sweep_interval {
            self.sweep_idle(now_secs);
            self.inserts_since_sweep = 0;
        }
        let mut evicted = None;
        if !self.inner.contains_key(&key) && self.inner.len() >= self.capacity {
            evicted = self.evict_oldest();
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.inner.insert(
            key.clone(),
            Timestamped {
                value,
                last_seen_secs: now_secs,
                seq,
            },
        );
        // A re-insert of an existing key leaves its previous (key, old_seq) entry
        // in `order`; that entry is now stale (its seq no longer matches the
        // key's live seq) and is skipped by both eviction and compaction.
        self.order.push_back((key, seq));
        if self.order.len() > self.capacity.saturating_mul(2) {
            self.compact_order();
        }
        self.gauge.set(self.inner.len());
        evicted
    }

    pub fn get(&mut self, key: &K, now_secs: u64) -> Option<&V> {
        match self.inner.get_mut(key) {
            Some(entry) => {
                entry.last_seen_secs = now_secs;
                Some(&entry.value)
            }
            None => None,
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// True when `(key, seq)` names a live key at its newest insert position.
    fn is_live_position(&self, key: &K, seq: u64) -> bool {
        matches!(self.inner.get(key), Some(entry) if entry.seq == seq)
    }

    fn compact_order(&mut self) {
        // Rebuild `order` from the live entries in seq order, dropping every
        // stale duplicate. O(n log n) but amortized over `capacity` inserts.
        let mut live: Vec<(K, u64)> = self
            .inner
            .iter()
            .map(|(k, entry)| (k.clone(), entry.seq))
            .collect();
        live.sort_by_key(|(_, seq)| *seq);
        self.order = live.into_iter().collect();
    }

    fn sweep_idle(&mut self, now_secs: u64) {
        if self.idle_ttl_secs == 0 {
            return;
        }
        let floor = now_secs.saturating_sub(self.idle_ttl_secs);
        self.inner.retain(|_, entry| entry.last_seen_secs > floor);
        let inner = &self.inner;
        self.order
            .retain(|(k, seq)| matches!(inner.get(k), Some(entry) if entry.seq == *seq));
        self.gauge.set(self.inner.len());
    }

    fn evict_oldest(&mut self) -> Option<(K, V)> {
        // Skip stale duplicate positions (a key whose live seq is newer than the
        // popped one) so a recently-refreshed key is never evicted ahead of a
        // genuinely-older key.
        while let Some((candidate, seq)) = self.order.pop_front() {
            if self.is_live_position(&candidate, seq) {
                if let Some(entry) = self.inner.remove(&candidate) {
                    self.gauge.set(self.inner.len());
                    return Some((candidate, entry.value));
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::{BoundedMap, SizeGauge};

    #[test]
    fn insert_evicts_oldest_at_cap_and_returns_it() {
        let gauge = SizeGauge::new();
        let mut map: BoundedMap<u32, u32> = BoundedMap::new(2, 0, gauge.clone());
        assert_eq!(map.insert(1, 10, 0), None);
        assert_eq!(map.insert(2, 20, 0), None);
        assert_eq!(map.len(), 2);
        // At cap: inserting a new key evicts the oldest-inserted (key 1).
        assert_eq!(map.insert(3, 30, 0), Some((1, 10)));
        assert_eq!(map.len(), 2);
        assert_eq!(gauge.get(), 2);
        assert_eq!(map.get(&1, 0), None);
        assert_eq!(map.get(&3, 0), Some(&30));
    }

    #[test]
    fn reinsert_moves_key_to_newest_so_refreshed_key_survives_eviction() {
        // Teeth: against a naive stale-duplicate `order`, evict_oldest pops the
        // front (stale) copy of the refreshed key and deletes its live entry.
        let gauge = SizeGauge::new();
        let mut map: BoundedMap<u32, u32> = BoundedMap::new(2, 0, gauge.clone());
        map.insert(1, 10, 0); // true-oldest so far
        map.insert(2, 20, 0);
        // Re-insert (refresh) key 1: it becomes newest, so key 2 is now oldest.
        map.insert(1, 11, 0);
        // Insert a new key at capacity: the true-oldest (key 2) must be evicted,
        // NOT the just-refreshed key 1.
        assert_eq!(
            map.insert(3, 30, 0),
            Some((2, 20)),
            "the genuinely-oldest key must be evicted, not the refreshed one"
        );
        assert_eq!(map.get(&1, 0), Some(&11), "refreshed key must survive");
        assert_eq!(map.get(&2, 0), None, "true-oldest key must be gone");
        assert_eq!(map.get(&3, 0), Some(&30));
        assert_eq!(map.len(), 2);
        assert_eq!(gauge.get(), 2);
    }

    #[test]
    fn many_reinserts_do_not_leak_order_or_breach_capacity() {
        // Drive far more re-inserts than 2*capacity so compaction runs and stale
        // duplicates are reclaimed; capacity and gauge must still hold.
        let gauge = SizeGauge::new();
        let mut map: BoundedMap<u32, u32> = BoundedMap::new(4, 0, gauge.clone());
        for round in 0..1000u32 {
            let key = round % 4; // only 4 distinct keys: all re-inserts
            let _ = map.insert(key, round, 0);
            assert!(map.len() <= 4, "capacity breached: {}", map.len());
            assert_eq!(map.len(), gauge.get(), "gauge desynced from len");
        }
        // All four keys present with their latest values.
        for key in 0..4u32 {
            assert!(map.get(&key, 0).is_some(), "live key {key} lost");
        }
    }

    #[test]
    fn sweep_idle_drops_expired_keeps_fresh() {
        let gauge = SizeGauge::new();
        // capacity high so eviction never fires; idle_ttl 10s; sweep every 256.
        let mut map: BoundedMap<u32, u32> = BoundedMap::new(4096, 10, gauge.clone());
        map.insert(1, 10, 100); // last_seen 100
        map.insert(2, 20, 100);
        // Refresh key 2 at t=105 so it survives a sweep at t=115.
        assert_eq!(map.get(&2, 105), Some(&20));
        // Force a sweep by driving 256 inserts at t=115; floor = 115 - 10 = 105.
        for k in 1000..1256u32 {
            map.insert(k, k, 115);
        }
        // Key 1 (last_seen 100 <= 105 floor) is swept; key 2 (last_seen 105) is
        // NOT > floor 105, so it is also swept. Refresh key 2 later to prove the
        // keep path independently.
        assert_eq!(map.get(&1, 115), None);

        let gauge2 = SizeGauge::new();
        let mut map2: BoundedMap<u32, u32> = BoundedMap::new(4096, 10, gauge2);
        map2.insert(1, 10, 100);
        assert_eq!(map2.get(&1, 200), Some(&10)); // refresh last_seen to 200
        for k in 1000..1256u32 {
            map2.insert(k, k, 205); // floor 195; key 1 last_seen 200 > 195 survives
        }
        assert_eq!(map2.get(&1, 205), Some(&10));
    }

    #[test]
    fn zero_capacity_disables_and_hands_pair_back() {
        let gauge = SizeGauge::new();
        let mut map: BoundedMap<u32, u32> = BoundedMap::new(0, 0, gauge.clone());
        assert_eq!(map.insert(1, 10, 0), Some((1, 10)));
        assert_eq!(map.len(), 0);
        assert_eq!(gauge.get(), 0);
    }
}

#[cfg(test)]
mod prop {
    use crate::{BoundedMap, SizeGauge};
    use proptest::prelude::*;

    #[derive(Debug, Clone)]
    enum Op {
        Insert(u8, u8, u64),
        Get(u8, u64),
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            (any::<u8>(), any::<u8>(), 0u64..1000).prop_map(|(k, v, t)| Op::Insert(k, v, t)),
            (any::<u8>(), 0u64..1000).prop_map(|(k, t)| Op::Get(k, t)),
        ]
    }

    proptest! {
        #[test]
        fn gauge_tracks_len_and_len_never_exceeds_capacity(
            cap in 1usize..64,
            ttl in 0u64..50,
            ops in prop::collection::vec(op_strategy(), 0..500),
        ) {
            let gauge = SizeGauge::new();
            let mut map: BoundedMap<u8, u8> = BoundedMap::new(cap, ttl, gauge.clone());
            for op in ops {
                match op {
                    Op::Insert(k, v, t) => { let _ = map.insert(k, v, t); }
                    Op::Get(k, t) => { let _ = map.get(&k, t); }
                }
                prop_assert!(map.len() <= cap, "len {} exceeded cap {}", map.len(), cap);
                prop_assert_eq!(map.len(), gauge.get(), "gauge desynced from len");
            }
        }
    }
}
