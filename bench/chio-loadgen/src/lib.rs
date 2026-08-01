//! Real-stack load generator for the Chio kernel and its SQLite receipt store.
//!
//! [`StackHarness`] boots a live [`chio_kernel::ChioKernel`] wired to a real
//! [`chio_store_sqlite::SqliteReceiptStore`] and a configurable-latency fixture
//! tool server, then drives allow-path dispatches through the unmodified kernel
//! evaluation pipeline. Every fallible boot and dispatch path yields a typed
//! [`LoadgenError`] and denies; there is no silent-success path.
//!
//! The gating entry point [`StackHarness::boot`] refuses a non-durable
//! in-memory store so a measurement or fault run cannot claim durability it does
//! not have. [`StackHarness::boot_smoke`] relaxes that boundary for local smoke
//! checks only.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::time::Duration;

pub mod rss;
mod stack;
mod sustained;

pub use stack::{DispatchOutcome, StackHarness};
pub use sustained::{enforce_budget, run_sustained, LoadReport};

/// Parameters for a load-generation run.
///
/// Field semantics: `arrival_rate_hz` is the target dispatch rate; `duration`
/// bounds a sustained run; `tool_latency` is the fixture tool server's per-invoke
/// sleep; `store` selects the receipt-store backing; `p99_budget` and
/// `rss_growth_budget_bytes` are the pass/fail thresholds a gating run enforces.
#[derive(Debug, Clone)]
pub struct LoadgenConfig {
    pub arrival_rate_hz: u32,
    pub duration: Duration,
    pub tool_latency: Duration,
    pub store: StoreBacking,
    pub p99_budget: Duration,
    pub rss_growth_budget_bytes: u64,
}

/// Receipt-store backing for a run. `Sqlite` is durable; `Memory` is a
/// non-durable smoke-only backing that a gating boot refuses.
#[derive(Debug, Clone)]
pub enum StoreBacking {
    Sqlite { path: PathBuf },
    Memory,
}

/// Typed failure surface for boot and dispatch. Every variant denies.
#[derive(Debug, thiserror::Error)]
pub enum LoadgenError {
    #[error("receipt store failed to open: {0}")]
    StoreOpen(String),
    #[error("a non-durable store (in-memory or transient) is not permitted in a gating run")]
    MemoryStoreRejectedInGate,
    #[error("kernel boot failed: {0}")]
    KernelBoot(String),
    #[error("dispatch failed mid-run: {0}")]
    Dispatch(String),
    #[error("arrival_rate_hz is zero; an uncapped rate is spelled as a large value, not 0")]
    ZeroArrivalRate,
    #[error(
        "arrival_rate_hz {arrival_rate_hz} exceeds the nanosecond pacer resolution of 1_000_000_000 Hz; dispatches cannot be spaced below one nanosecond"
    )]
    ArrivalRateTooHigh { arrival_rate_hz: u32 },
    #[error("sustained run completed no successful calls")]
    EmptyRun,
    #[error(
        "configured schedule requires {scheduled} dispatches, above the bounded maximum of {maximum}"
    )]
    DispatchScheduleTooLarge { scheduled: u128, maximum: u64 },
    #[error(
        "configured arrival schedule missed: required {scheduled} dispatches, attempted {attempted}, completed {completed}"
    )]
    ArrivalRateMissed {
        scheduled: u64,
        attempted: u64,
        completed: u64,
    },
    #[error(
        "resident-set size was never measured, so the growth budget cannot be proven satisfied"
    )]
    RssUnmeasured,
    #[error("p99 {observed_nanos}ns exceeded budget {budget_nanos}ns")]
    P99Exceeded {
        observed_nanos: u128,
        budget_nanos: u128,
    },
    #[error("RSS grew {grew_bytes} bytes over budget {budget_bytes}")]
    RssGrowthExceeded { grew_bytes: u64, budget_bytes: u64 },
    #[error("run duration is too large to schedule on the monotonic clock")]
    DurationTooLong,
}
