//! Mobile device-attestation verifiers.

pub mod app_attest;
pub mod apple_root;
pub mod errors;

pub use app_attest::{
    verify_app_attest, AppAttestVerificationInput, VerifiedAppAttest, APP_ATTEST_FORMAT,
};
pub use errors::AttestationError;
