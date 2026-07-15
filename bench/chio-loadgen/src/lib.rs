//! Real-stack load generator for the Chio kernel and its SQLite receipt store.
//!
//! [`StackHarness`] boots a live [`chio_kernel::ChioKernel`] wired to a real
//! [`chio_store_sqlite::SqliteReceiptStore`] and a configurable-latency stub
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

pub use stack::StackHarness;
pub use sustained::{enforce_budget, run_sustained, LoadReport};

/// Parameters for a load-generation run.
///
/// Field semantics: `arrival_rate_hz` is the target dispatch rate; `duration`
/// bounds a sustained run; `tool_latency` is the stub tool server's per-invoke
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
    #[error("in-memory store is not permitted in a gating run")]
    MemoryStoreRejectedInGate,
    #[error("kernel boot failed: {0}")]
    KernelBoot(String),
    #[error("dispatch failed mid-run: {0}")]
    Dispatch(String),
    #[error("p99 {observed_ms}ms exceeded budget {budget_ms}ms")]
    P99Exceeded { observed_ms: u128, budget_ms: u128 },
    #[error("RSS grew {grew_bytes} bytes over budget {budget_bytes}")]
    RssGrowthExceeded { grew_bytes: u64, budget_bytes: u64 },
}
