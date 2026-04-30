//! Chio model-card surface.
//!
//! M10 phase 4 introduces signed model cards that bind a provider's
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
//! from the M01 registry.
//!
//! # Crate surface (P4 layout)
//!
//! - `card` -- model card schema and the `ModelCard` type with RFC 8785
//!   canonical-JSON encoding (P4.T2).
//! - `bundle` -- cosign bundle helper that consumes
//!   [`chio_attest_verify::SigstoreVerifier::verify_bundle`] (P4.T3).
//!
//! Subsequent tickets (kernel binding refusal, `arc bind --card` CLI)
//! consume this surface from `chio-kernel` and `chio-cli` respectively.
//!
//! # Forbidden constructs
//!
//! Per the workspace EXECUTION-BOARD policy "No verifier or trust-boundary
//! stubs", this crate forbids `unsafe`, `unwrap`, and `expect` at the lint
//! level. PRs touching this crate also require a
//! `rg -n 'todo!\(|unimplemented!\(|panic!\('` sweep across `src/` and
//! `tests/`.

#![forbid(unsafe_code)]
#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]
