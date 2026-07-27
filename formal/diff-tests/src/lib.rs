//! Differential testing: executable Chio reference spec vs the production
//! capability structs and the normalized proof-facing AST in `chio-kernel-core`.
//!
//! This crate is the shipped proof-style release gate for scope attenuation
//! semantics and the bounded treaty predicate fragment. The treaty oracle is
//! independent differential evidence. It does not establish a Lean extraction
//! or whole-runtime refinement proof.

pub mod generators;
pub mod spec;
