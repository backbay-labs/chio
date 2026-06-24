//! Chio hardware custody surface.
//!
//! The crate owns the WebAuthn assertion verifier surface, the
//! audience-pinned `PasskeyCapability` envelope, and an issuer service
//! that signs every capability it mints through its signing backend
//! (`Ed25519Backend`, the FIPS P-256/P-384 backends, or `HybridBackend`
//! under the `pq` feature). The issuer fails closed if no signing backend
//! is wired: it never emits an unsigned capability. Issuance is gated by a
//! per-subject rate limiter, a per-credential replay nonce store, and the
//! revocation cascade, all consulted before a signature is produced.
//!
//! # Trust boundary
//!
//! Every public method that produces an `Ok(_)` result MUST mean the call
//! satisfied the named precondition fully. There is no path through this
//! crate that returns `Ok(_)` on a partial verification: bad inputs return
//! [`error::CustodyError`] variants that carry stable
//! `urn:chio:error:custody:*` codes from the canonical error registry.
//!
//! Browser clients MUST NOT hold root capability or issuer signing material;
//! they present a WebAuthn assertion to the issuer surface in
//! [`issuer`] and receive a short-lived audience-pinned capability minted
//! server-side.
//!
//! # Forbidden constructs
//!
//! No verifier or trust-boundary stubs: this crate forbids `unsafe`,
//! `unwrap`, and `expect` at the lint level.

#![forbid(unsafe_code)]
#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

pub mod attestation;
pub mod capability;
pub mod error;
pub mod issuer;
pub mod mint;
pub mod nonce_store;
pub mod rate_limit;
pub mod revocation;
pub mod verifier;

pub use attestation::{
    verify_app_attest, verify_mobile_receipt_chain, verify_play_integrity,
    AppAttestVerificationInput, AttestationError, PlayIntegrityVerificationInput,
    VerifiedAppAttest, VerifiedMobileReceiptChain, VerifiedPlayIntegrity, APP_ATTEST_FORMAT,
    MEETS_DEVICE_INTEGRITY, PLAY_RECOGNIZED,
};
pub use capability::{PasskeyCapability, ScopeSet};
pub use error::CustodyError;
pub use issuer::{IssuerService, MintRequest, MintResponse};
pub use mint::{sign_capability, signing_message};
#[cfg(feature = "sqlite-store")]
pub use nonce_store::SqlitePasskeyNonceStore;
pub use nonce_store::{
    InMemoryPasskeyNonceStore, PasskeyNonceStore, RecordOutcome, DEFAULT_CLOCK_SKEW_SECONDS,
};
pub use rate_limit::{
    IssuanceRateLimiter, RateLimitOutcome, RateLimiter, DEFAULT_MAX_PER_WINDOW,
    DEFAULT_WINDOW_SECONDS,
};
#[cfg(feature = "sqlite-store")]
pub use revocation::SqliteCredentialRevocationOracle;
pub use revocation::{
    credential_revocation_nonce, CredentialRevocationOracle, InMemoryCredentialRevocationOracle,
    CREDENTIAL_REVOCATION_NONCE_VALUE,
};
#[cfg(feature = "passkey")]
pub use verifier::PasskeyVerifier;
pub use verifier::VerifiedAssertion;
