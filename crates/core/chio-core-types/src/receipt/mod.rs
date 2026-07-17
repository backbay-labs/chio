//! Chio receipts: signed proof that a tool call was evaluated.
//!
//! Every tool invocation -- whether allowed or denied -- produces a receipt.
//! Receipts are the immutable audit trail of the Chio protocol.

pub mod authoritative_spend;
pub mod body;
pub mod checkpoint;
pub mod crypto_floor;
pub mod decision;
pub mod economics;
pub mod governance;
pub mod kinds;
pub mod lineage;
pub mod metadata;
pub mod signing;
pub(crate) mod validation;

pub use authoritative_spend::{
    is_authoritative_spend_receipt, BudgetAuthorityReceiptRef, NotAuthoritativeReason,
    PresentedNonceView, MEDIATED_SPEND_PROFILE,
};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
