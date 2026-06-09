//! Data layer guards for the Chio runtime kernel.
//!
//! This crate houses guards that inspect the *semantics* of data-store
//! accesses rather than merely the presence of a tool.  [`SqlQueryGuard`]
//! parses SQL queries submitted to database tools and enforces allowlists
//! on operations, tables, columns, and predicates.
//!
//! The crate also ships `VectorDbGuard`, `WarehouseCostGuard`, and the
//! post-invocation `QueryResultGuard`. The module layout is designed to
//! absorb further additions without breaking the public surface.
//!
//! # Relationship to `chio-guards`
//!
//! `chio-data-guards` is a *sibling* of `chio-guards`.  It reuses the
//! [`chio_kernel::Guard`] trait and the [`chio_guards::extract_action_checked`]
//! dispatcher; it does not redefine either.  Pipelines compose the two
//! crates transparently:
//!
//! ```ignore
//! use chio_guards::GuardPipeline;
//! use chio_data_guards::{SqlGuardConfig, SqlQueryGuard};
//!
//! let mut pipeline = GuardPipeline::default_pipeline();
//! pipeline.add(Box::new(SqlQueryGuard::new(SqlGuardConfig::default())));
//! ```
//!
//! # Fail-closed
//!
//! Every guard in this crate is fail-closed.  Parse errors deny, empty
//! configurations deny, and invalid user-supplied regex configuration
//! rejects policy loading or constructs a deny-all guard.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod config;
pub mod error;
pub mod result_guard;
pub mod sql_guard;
pub mod sql_parser;
pub mod vector_guard;
pub mod warehouse_cost_guard;

pub use config::{SqlDialect, SqlGuardConfig, SqlOperation};
pub use error::SqlGuardDenyReason;
pub use result_guard::{
    QueryResultGuard, QueryResultGuardConfig, QueryResultHook, DEFAULT_REDACTION_MARKER,
};
pub use sql_guard::SqlQueryGuard;
pub use sql_parser::SqlAnalysis;
pub use vector_guard::{
    VectorCall, VectorDbGuard, VectorFieldPaths, VectorGuardConfig, VectorGuardDenyReason,
};
pub use warehouse_cost_guard::{
    DryRunEstimate, WarehouseCostDenyReason, WarehouseCostFieldPaths, WarehouseCostGuard,
    WarehouseCostGuardConfig,
};
