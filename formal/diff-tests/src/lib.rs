//! Differential testing: executable Chio reference spec vs the production
//! capability structs and the normalized proof-facing AST in `chio-kernel-core`.
//!
//! This crate is the shipped proof-style release gate for scope attenuation
//! semantics. Lean assets remain advisory until they are root-imported and
//! `sorry`-free.

pub mod counterexample;

pub mod generators;
#[cfg(not(target_arch = "wasm32"))]
#[path = "../../itf/receipt_before_allow.rs"]
mod receipt_before_allow_trace;
pub mod spec;
