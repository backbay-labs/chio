//! Shared cross-protocol bridge contracts and runtime orchestration substrate.
//!
//! This crate centralizes the reusable types needed by outward protocol edges
//! so each bridge path shares one definition of provenance, attenuation, and
//! receipt-lineage behavior rather than redefining it independently.

#![forbid(unsafe_code)]

pub mod capability_bridge;
pub mod discovery;
pub mod error;
pub mod execution;
pub mod lifecycle;
pub mod orchestrator;
pub mod routing;
pub mod semantic_hints;
pub mod sync_bridge_shared;
mod validation;

#[cfg(test)]
mod tests;
