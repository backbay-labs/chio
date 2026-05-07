//! Re-exports of the typed HTTP egress contract.
//!
//! The actual types live in the leaf crate `chio-egress-contract` so that
//! caller crates outside the `chio-kernel` dependency graph (for example,
//! `chio-link`, which `chio-kernel` itself depends on) can pull the contract
//! without forming a dependency cycle.
pub use chio_egress_contract::{HttpEgressContract, HttpEgressError, ValidatedHttpEgressTarget};

#[cfg(feature = "reqwest-egress")]
#[allow(unused_imports)]
pub use chio_egress_contract::{client_builder_with_contract, send_with_contract};
