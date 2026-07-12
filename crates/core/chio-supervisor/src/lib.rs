//! Task supervision and honest health for Chio serving processes.
//!
//! A long-lived background worker that dies or wedges while its health surface keeps
//! reporting green is the failure mode this crate exists to prevent. Each supervised
//! worker retains its join handle, restarts with capped backoff on a caught panic or
//! a restart-worthy exit, and, after a bounded number of failures, trips a persistent
//! [`HealthFlag`] that the surfaces operators poll must report.
//!
//! Two properties are load-bearing:
//!
//! - Honesty. A tripped flag never clears itself on a later lucky success. A worker
//!   that recovered but lost work in the gap must still report the gap; the only path
//!   back to [`HealthLevel::Healthy`] is an explicit, operator-visible
//!   [`HealthFlag::clear`].
//! - Fail closed. A [`HealthFlag`] marked TCB-critical reports
//!   [`HealthFlag::is_serving_closed`] the moment it leaves `Healthy`, so a caller can
//!   deny work before it executes rather than after.
//!
//! This is a zero-Chio-dependency leaf crate by design: the kernel receipt writer,
//! the control-plane sync loop, and the SIEM exporter can each supervise their work
//! without taking a dependency on one another or dragging the trusted computing base
//! into the isolated telemetry pipeline.

mod config;
mod health;
mod sync;
mod thread;
mod time;

#[cfg(feature = "async")]
mod task;

pub use config::{SupervisedOutcome, SupervisorConfig};
pub use health::{HealthFlag, HealthLevel, HealthSnapshot};
pub use thread::SupervisedThread;
pub use time::now_unix_ms;

#[cfg(feature = "async")]
pub use task::{supervise_task, SupervisedTask};
