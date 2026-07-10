//! Atomic / Arc shim. Under `--cfg loom` these resolve to loom's models so the
//! concurrency test in `tests/loom_bounded_map.rs` can explore interleavings;
//! otherwise they are the std types with zero overhead.

#[cfg(loom)]
pub(crate) use loom::sync::atomic::{AtomicUsize, Ordering};
#[cfg(loom)]
pub(crate) use loom::sync::Arc;

#[cfg(not(loom))]
pub(crate) use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(not(loom))]
pub(crate) use std::sync::Arc;
