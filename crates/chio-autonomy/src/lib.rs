//! Chio autonomous pricing, capital optimization, and fail-safe automation types.
//!
//! These contracts extend the delegated underwriting, market, capital, and
//! web3 surfaces into one bounded automation layer. The automation layer
//! remains evidence-referential: it carries explicit references back to prior
//! Chio truth rather than replacing those signed artifacts.

#![forbid(unsafe_code)]

pub use chio_core_types::{capability, receipt};
pub use chio_market as market;
pub use chio_web3 as web3;

mod error;
mod model;
mod validation;

pub use error::AutonomyContractError;
pub use model::*;
pub use validation::{
    validate_autonomous_comparison_report, validate_autonomous_drift_report,
    validate_autonomous_execution_decision, validate_autonomous_pricing_authority_envelope,
    validate_autonomous_pricing_decision, validate_autonomous_pricing_input,
    validate_autonomous_qualification_matrix, validate_autonomous_rollback_plan,
    validate_capital_pool_optimization, validate_capital_pool_simulation_report,
};

#[cfg(test)]
mod tests;
