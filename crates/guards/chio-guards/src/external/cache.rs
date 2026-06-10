//! TTL cache with LRU eviction for external guard verdicts.
//!
//! [`TtlCache`] is a thread-safe bounded cache that stores values with a
//! per-entry monotonic deadline. Entries evict either when their TTL expires
//! (on access or on `prune`) or when the cache reaches its capacity (least
//! recently used eviction).
//!
//! The cache uses a [`Clock`] abstraction for the "now" timestamp so that
//! tests can drive time via [`tokio::time::pause`] + `advance` without any
//! wall-clock sleep.

use std::collections::HashMap;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

/// Clock abstraction used by the cache and other resilience primitives.
///
/// The default implementation reads from [`tokio::time::Instant::now`], which
/// honors [`tokio::time::pause`]/`advance` in tests. Callers with a custom
/// time source may provide their own implementation.
pub trait Clock: Send + Sync + 'static {
    /// Return the current monotonic instant.
    fn now(&self) -> Instant;
}

/// Default [`Clock`] implementation backed by Tokio's pausable timer.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioClock;

impl Clock for TokioClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Entry stored in the TTL cache.
#[derive(Debug, Clone)]
struct Entry<V> {
    value: V,
    expires_at: Instant,
    /// Monotonically increasing recency counter. Higher = more recent.
    recency: u64,
}

/// Thread-safe TTL cache with LRU eviction.
///
/// The cache is keyed by any `Eq + Hash + Clone` type and stores any
/// `Clone` value. Each `insert` takes a per-entry TTL. Entries expire on
/// the first `get`/`insert` that observes the expired deadline; an explicit
/// [`TtlCache::prune`] is also provided for bulk collection.
pub struct TtlCache<K, V> {
    inner: Mutex<CacheInner<K, V>>,
    capacity: NonZeroUsize,
    clock: Arc<dyn Clock>,
}

struct CacheInner<K, V> {
    entries: HashMap<K, Entry<V>>,
    /// Monotonic counter used to stamp entry recency.
    counter: u64,
}

impl<K, V> TtlCache<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    /// Create a new cache with the given capacity, backed by [`TokioClock`].
    ///
    /// Capacity is a non-zero usize because a zero-capacity cache is
    /// degenerate (every insert would immediately evict itself).
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self::with_clock(capacity, Arc::new(TokioClock))
    }

    /// Create a cache backed by a custom [`Clock`] implementation.
    pub fn with_clock(capacity: NonZeroUsize, clock: Arc<dyn Clock>) -> Self {
        Self {
            inner: Mutex::new(CacheInner {
                entries: HashMap::with_capacity(capacity.get()),
                counter: 0,
            }),
            capacity,
            clock,
        }
    }

    /// Configured maximum number of live entries.
    pub fn capacity(&self) -> usize {
        self.capacity.get()
    }

    /// Current number of entries in the cache (may include not-yet-pruned
    /// expired entries).
    pub fn len(&self) -> usize {
        let Ok(inner) = self.inner.lock() else {
            return 0;
        };
        inner.entries.len()
    }

    /// Returns true when the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Look up `key`. Returns `Some(value)` on cache hit (and bumps the
    /// entry's recency); `None` on miss or expired entry. Expired entries
    /// are removed on observation.
    pub fn get(&self, key: &K) -> Option<V> {
        let now = self.clock.now();
        let Ok(mut inner) = self.inner.lock() else {
            return None;
        };
        let expired = inner
            .entries
            .get(key)
            .map(|entry| entry.expires_at <= now)
            .unwrap_or(false);
        if expired {
            inner.entries.remove(key);
            return None;
        }
        inner.counter = inner.counter.saturating_add(1);
        let counter = inner.counter;
        let entry = inner.entries.get_mut(key)?;
        entry.recency = counter;
        Some(entry.value.clone())
    }

    /// Insert `value` under `key` with the given `ttl`. If the cache is at
    /// capacity, evicts the least recently used live entry first.
    pub fn insert(&self, key: K, value: V, ttl: Duration) {
        let now = self.clock.now();
        let expires_at = now.checked_add(ttl).unwrap_or(now);
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };

        inner.counter = inner.counter.saturating_add(1);
        let recency = inner.counter;

        // Replace existing entry directly.
        if let Some(entry) = inner.entries.get_mut(&key) {
            entry.value = value;
            entry.expires_at = expires_at;
            entry.recency = recency;
            return;
        }

        // Evict expired entries first, then LRU if still at capacity.
        if inner.entries.len() >= self.capacity.get() {
            evict_expired(&mut inner.entries, now);
        }
        if inner.entries.len() >= self.capacity.get() {
            evict_lru(&mut inner.entries);
        }

        inner.entries.insert(
            key,
            Entry {
                value,
                expires_at,
                recency,
            },
        );
    }

    /// Remove every entry whose TTL has expired relative to the clock's
    /// current "now". Returns the number of entries removed.
    pub fn prune(&self) -> usize {
        let now = self.clock.now();
        let Ok(mut inner) = self.inner.lock() else {
            return 0;
        };
        evict_expired(&mut inner.entries, now)
    }

    /// Remove all entries.
    pub fn clear(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.entries.clear();
        }
    }
}

fn evict_expired<K, V>(entries: &mut HashMap<K, Entry<V>>, now: Instant) -> usize
where
    K: Eq + Hash + Clone,
{
    let expired: Vec<K> = entries
        .iter()
        .filter_map(|(k, entry)| {
            if entry.expires_at <= now {
                Some(k.clone())
            } else {
                None
            }
        })
        .collect();
    let removed = expired.len();
    for k in expired {
        entries.remove(&k);
    }
    removed
}

fn evict_lru<K, V>(entries: &mut HashMap<K, Entry<V>>)
where
    K: Eq + Hash + Clone,
{
    let victim = entries
        .iter()
        .min_by_key(|(_, entry)| entry.recency)
        .map(|(k, _)| k.clone());
    if let Some(key) = victim {
        entries.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nz(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).expect("non-zero capacity")
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn insert_and_get_returns_value() {
        let cache: TtlCache<&'static str, u32> = TtlCache::new(nz(4));
        cache.insert("k", 42, Duration::from_secs(30));
        assert_eq!(cache.get(&"k"), Some(42));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn expired_entry_returns_none() {
        let cache: TtlCache<&'static str, u32> = TtlCache::new(nz(4));
        cache.insert("k", 42, Duration::from_secs(1));
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(cache.get(&"k"), None);
        assert!(cache.is_empty());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn lru_eviction_when_capacity_exceeded() {
        let cache: TtlCache<&'static str, u32> = TtlCache::new(nz(2));
        cache.insert("a", 1, Duration::from_secs(60));
        cache.insert("b", 2, Duration::from_secs(60));
        // Touch "a" so "b" becomes LRU.
        let _ = cache.get(&"a");
        cache.insert("c", 3, Duration::from_secs(60));
        assert_eq!(cache.get(&"a"), Some(1));
        assert_eq!(cache.get(&"b"), None);
        assert_eq!(cache.get(&"c"), Some(3));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn prune_removes_only_expired() {
        let cache: TtlCache<&'static str, u32> = TtlCache::new(nz(4));
        cache.insert("short", 1, Duration::from_secs(1));
        cache.insert("long", 2, Duration::from_secs(60));
        tokio::time::advance(Duration::from_secs(2)).await;
        let removed = cache.prune();
        assert_eq!(removed, 1);
        assert_eq!(cache.get(&"short"), None);
        assert_eq!(cache.get(&"long"), Some(2));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn overwrite_updates_value_and_ttl() {
        let cache: TtlCache<&'static str, u32> = TtlCache::new(nz(2));
        cache.insert("k", 1, Duration::from_secs(1));
        cache.insert("k", 2, Duration::from_secs(30));
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(cache.get(&"k"), Some(2));
    }
}
