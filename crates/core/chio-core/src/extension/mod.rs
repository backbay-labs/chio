//! Chio extension and official-stack contract types.
//!
//! These types freeze which Chio surfaces are canonical truth, which seams are
//! replaceable, how custom implementations negotiate against the official
//! stack, and which fail-closed conditions must be preserved.

mod error;
mod model;
mod negotiation;
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
mod validation;

pub use error::ExtensionContractError;
pub use model::*;
pub use negotiation::negotiate_extension;
pub use validation::{
    validate_extension_inventory, validate_extension_manifest, validate_official_stack_package,
    validate_qualification_matrix,
};

pub const CHIO_EXTENSION_INVENTORY_SCHEMA: &str = "chio.extension-inventory.v1";
pub const CHIO_EXTENSION_MANIFEST_SCHEMA: &str = "chio.extension-manifest.v1";
pub const CHIO_EXTENSION_NEGOTIATION_SCHEMA: &str = "chio.extension-negotiation.v1";
pub const CHIO_OFFICIAL_STACK_SCHEMA: &str = "chio.official-stack.v1";
pub const CHIO_EXTENSION_QUALIFICATION_MATRIX_SCHEMA: &str =
    "chio.extension-qualification-matrix.v1";
