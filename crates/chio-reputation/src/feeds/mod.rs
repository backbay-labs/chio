//! Bundled `ReputationFeed` implementations.
//!
//! Two feeds ship in this crate today:
//!
//! - [`arena_survival::ArenaSurvivalFeed`] consumes arena round outputs
//!   and rewards publishers whose guard bundles survive adversarial
//!   rounds.
//! - [`cross_provider_equality::CrossProviderEqualityFeed`] consumes
//!   verdict-matrix outputs and rewards publishers whose guard verdicts
//!   agree across providers.
//!
//! Both feeds are pure: their inputs are caller-provided thin
//! observation structs, not crate-level dependencies on `chio-arena` or
//! `chio-conformance`. Feeds stay deterministic functions from observed
//! signal to score delta and do not call back into the kernel. Keeping
//! the input shapes local to this crate also avoids a
//! `chio-reputation -> chio-arena` dependency cycle and lets audits
//! reproduce feeds offline against fixture data.

pub mod arena_survival;
pub mod cross_provider_equality;
