use std::collections::VecDeque;

use crate::SizeGauge;

/// Fixed-capacity append-only ring for process-local mirrors. `capacity == 0`
/// means "disabled" (stores nothing, hands each item straight back), the
/// correct default when a durable store is authoritative.
///
/// `Clone` produces a snapshot with its OWN independent `SizeGauge`, seeded to
/// the current length. `push` is public, so a clone can be appended to; giving
/// the clone a fresh gauge guarantees that writing through a snapshot (for
/// example the public `append` on a `receipt_log()` snapshot) can never corrupt
/// the owning structure's telemetry gauge.
#[derive(Debug)]
pub struct Ring<T> {
    buf: VecDeque<T>,
    capacity: usize,
    gauge: SizeGauge,
}

impl<T: Clone> Clone for Ring<T> {
    fn clone(&self) -> Self {
        // Independent gauge: the snapshot tracks only its own length so pushes
        // to the clone never write through to the owner's gauge handle.
        let gauge = SizeGauge::new();
        gauge.set(self.buf.len());
        Self {
            buf: self.buf.clone(),
            capacity: self.capacity,
            gauge,
        }
    }
}

impl<T> Ring<T> {
    pub fn with_capacity(capacity: usize, gauge: SizeGauge) -> Self {
        Self {
            buf: VecDeque::new(),
            capacity,
            gauge,
        }
    }

    /// Push, evicting the oldest entry when at capacity. Returns the evicted
    /// item (if any) so callers may act before it drops. Never grows past
    /// `capacity`.
    pub fn push(&mut self, item: T) -> Option<T> {
        if self.capacity == 0 {
            return Some(item);
        }
        let evicted = if self.buf.len() >= self.capacity {
            self.buf.pop_front()
        } else {
            None
        };
        self.buf.push_back(item);
        self.gauge.set(self.buf.len());
        evicted
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.buf.iter()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use crate::{Ring, SizeGauge};

    #[test]
    fn push_never_exceeds_capacity_and_returns_evicted() {
        let gauge = SizeGauge::new();
        let mut ring: Ring<u32> = Ring::with_capacity(3, gauge.clone());
        assert_eq!(ring.push(1), None);
        assert_eq!(ring.push(2), None);
        assert_eq!(ring.push(3), None);
        assert_eq!(ring.len(), 3);
        assert_eq!(gauge.get(), 3);
        // At capacity: the oldest (1) is evicted and returned.
        assert_eq!(ring.push(4), Some(1));
        assert_eq!(ring.len(), 3);
        assert_eq!(gauge.get(), 3);
        let items: Vec<u32> = ring.iter().copied().collect();
        assert_eq!(items, vec![2, 3, 4]);
    }

    #[test]
    fn clone_has_independent_gauge_so_snapshot_pushes_do_not_corrupt_owner() {
        let owner_gauge = SizeGauge::new();
        let mut ring: Ring<u32> = Ring::with_capacity(4, owner_gauge.clone());
        ring.push(1);
        ring.push(2);
        assert_eq!(owner_gauge.get(), 2);

        // A snapshot clone must not share the owner's gauge handle.
        let mut snapshot = ring.clone();
        assert_eq!(snapshot.len(), 2);
        snapshot.push(3);
        snapshot.push(4);
        // The clone tracks its own length; the owner's gauge is untouched.
        assert_eq!(snapshot.len(), 4);
        assert_eq!(
            owner_gauge.get(),
            2,
            "owner gauge corrupted by a push to a snapshot clone"
        );
    }

    #[test]
    fn zero_capacity_stores_nothing_and_hands_item_back() {
        let gauge = SizeGauge::new();
        let mut ring: Ring<u32> = Ring::with_capacity(0, gauge.clone());
        assert_eq!(ring.push(7), Some(7));
        assert_eq!(ring.len(), 0);
        assert!(ring.is_empty());
        assert_eq!(gauge.get(), 0);
    }
}
