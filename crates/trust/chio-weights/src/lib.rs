//! Chio model-card surface.
//!
//! Signed model cards bind a provider's
//! `(weights_hash, allowed_capability_set, banned_tools, training_data_class)`
//! to a cosign-signed envelope. The kernel refuses to bind a provider whose
//! loaded weights or requested scopes do not match the card.
//!
//! # Trust boundary
//!
//! Every public method that produces an `Ok(_)` result MUST mean the call
//! satisfied the named precondition fully. There is no path through this
//! crate that returns `Ok(_)` on a partial verification: bad inputs return
//! typed error variants that carry stable `urn:chio:error:weights:*` codes
//! from the workspace error-code registry.
//!
//! # Crate surface
//!
//! - `card` -- model card schema and the `ModelCard` type with RFC 8785
//!   canonical-JSON encoding.
//! - `bundle` -- cosign bundle helper that consumes
//!   [`chio_attest_verify::SigstoreVerifier::verify_bundle`].
//! - `lineage` -- lineage-anchor proof helpers for published model cards.
//!
//! The kernel binding refusal and `chio bind --card` CLI consume this
//! surface from `chio-kernel` and `chio-cli` respectively.
//!
//! # Forbidden constructs
//!
//! No verifier or trust-boundary stubs: this crate forbids `unsafe`,
//! `unwrap`, and `expect` at the lint level.

#![forbid(unsafe_code)]
#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

pub mod bundle;
pub mod card;
pub mod error;
pub mod lineage;

#[cfg(kani)]
mod kani_public_harnesses;

pub use bundle::{verify_model_card_bundle, VerifiedModelCard};
pub use card::{weights_hash_of, ModelCard, StringSet, CARD_VERSION_V1};
pub use error::WeightsError;
pub use lineage::{
    anchor_model_card, verify_model_card_anchor, ModelCardLineageAnchor, MODEL_CARD_ANCHOR_SCHEMA,
};
