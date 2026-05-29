#![forbid(unsafe_code)]

//! Sustained-load capacity harness for the healthcare design-partner pilot.
//!
//! The crate is intentionally deterministic in PR-tier gates. Real traffic
//! capture is owned by `scripts/shadow-capture.sh`; this library converts the
//! captured baseline into the 1x / 2x / 5x report shape committed to the audit
//! doc.

pub mod runner;

pub use runner::{
    run_capacity_profile, CapacityReport, CapacitySample, ReplayInput, ReplayMultiple,
    DEFAULT_BASELINE_RECEIPTS_PER_DAY,
};
