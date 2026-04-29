//! Epoch identifiers for hot-swapped WASM guard modules.

use std::fmt;

/// Monotonic identifier assigned to a loaded guard module.
///
/// Epoch zero is the initial module loaded with a guard. Later module swaps
/// use strictly increasing epoch identifiers so callers can correlate an
/// evaluation with the module version that handled it.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Deserialize,
    serde::Serialize,
)]
pub struct EpochId(u64);

impl EpochId {
    /// Initial epoch for a newly loaded guard module.
    pub const INITIAL: Self = Self(0);

    /// Create an epoch identifier from its raw integer value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the raw integer value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Return the next epoch identifier, or `None` if the counter would
    /// overflow.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

impl From<u64> for EpochId {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<EpochId> for u64 {
    fn from(epoch: EpochId) -> Self {
        epoch.get()
    }
}

impl fmt::Display for EpochId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_id_initial_starts_at_zero() {
        assert_eq!(EpochId::INITIAL.get(), 0);
        assert_eq!(EpochId::default(), EpochId::INITIAL);
    }

    #[test]
    fn epoch_id_next_is_monotonic() {
        let first = EpochId::INITIAL;
        let second = first.next().unwrap();
        let third = second.next().unwrap();

        assert!(first < second);
        assert!(second < third);
        assert_eq!(u64::from(third), 2);
    }

    #[test]
    fn epoch_id_next_returns_none_on_overflow() {
        assert!(EpochId::new(u64::MAX).next().is_none());
    }

    #[test]
    fn epoch_id_display_uses_raw_value() {
        assert_eq!(EpochId::new(42).to_string(), "42");
    }
}
