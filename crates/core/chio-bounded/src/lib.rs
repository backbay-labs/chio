//! Reusable bounded in-memory collections for Chio serving processes.
//!
//! Core invariant: no long-lived collection in a serving process may exist
//! without (1) a capacity policy (ring, LRU, idle-sweep, or deny-at-cap) and
//! (2) a live size metric. This crate is the substrate: `Ring` and `BoundedMap`
//! each own a cloneable `SizeGauge`.

mod bounded_map;
mod gauge;
mod ring;
mod sync;

pub use bounded_map::BoundedMap;
pub use gauge::SizeGauge;
pub use ring::Ring;
