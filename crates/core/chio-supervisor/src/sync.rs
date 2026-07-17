//! Atomic / Arc / Mutex shim. Under `--cfg loom` these resolve to loom's models
//! so the concurrency test in `tests/loom_health.rs` can explore interleavings of
//! a worker recording failures against a reader taking a snapshot; otherwise they
//! are the std types with zero overhead.

#[cfg(loom)]
pub(crate) use loom::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
#[cfg(loom)]
pub(crate) use loom::sync::{Arc, Mutex};

#[cfg(not(loom))]
pub(crate) use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
#[cfg(not(loom))]
pub(crate) use std::sync::{Arc, Mutex};
