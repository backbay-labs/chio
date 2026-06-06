//! Shared cross-protocol bridge contracts and runtime orchestration substrate.
//!
//! This crate centralizes the reusable types needed by outward protocol edges
//! so A2A, ACP, and later MCP/OpenAI/HTTP bridge paths do not each redefine
//! provenance, attenuation, and receipt-lineage behavior independently.

#![forbid(unsafe_code)]

pub mod capability_bridge;
pub mod discovery;
pub mod error;
pub mod execution;
pub mod lifecycle;
pub mod orchestrator;
pub mod routing;
pub mod semantic_hints;
mod validation;

#[cfg(test)]
mod tests;
