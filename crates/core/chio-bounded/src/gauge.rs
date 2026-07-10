use crate::sync::{Arc, AtomicUsize, Ordering};

/// Live entry-count gauge for a bounded structure. Cloneable handle so a
/// telemetry exporter can read the count without locking the structure that
/// owns it.
#[derive(Clone, Debug)]
pub struct SizeGauge(Arc<AtomicUsize>);

#[cfg(not(loom))]
impl Default for SizeGauge {
    fn default() -> Self {
        Self::new()
    }
}

impl SizeGauge {
    pub fn new() -> Self {
        Self(Arc::new(AtomicUsize::new(0)))
    }

    pub fn get(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }

    pub(crate) fn set(&self, value: usize) {
        self.0.store(value, Ordering::Relaxed);
    }
}
