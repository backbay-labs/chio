//! Bundled `ReputationFeed` implementations.
//!
//! Two feeds ship in this crate today:
//!
//! - [`arena_survival::ArenaSurvivalFeed`] consumes trajectory-2 M08 arena
//!   round outputs and rewards publishers whose guard bundles survive
//!   adversarial rounds.
//! - [`cross_provider_equality::CrossProviderEqualityFeed`] consumes
//!   trajectory-1 M07 verdict-matrix outputs and rewards publishers whose
//!   guard verdicts agree across providers.
//!
//! Both feeds are pure: their inputs are caller-provided thin observation
//! structs, not crate-level dependencies on `chio-arena` or
//! `chio-conformance`. Per the M09 P2-P4 economics readiness research doc,
//! "feeds should stay deterministic functions from observed signal to score
//! delta and should not call back into the kernel." Keeping the input shapes
//! local to this crate also avoids a `chio-reputation -> chio-arena`
//! dependency cycle and lets the audit doc reproduce feeds offline against
//! fixture data.

pub mod arena_survival;
