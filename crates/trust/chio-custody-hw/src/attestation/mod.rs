//! Mobile device-attestation verifiers.

pub mod app_attest;
pub mod apple_root;
pub mod errors;
pub mod google_root;
pub mod play_integrity;
pub mod receipt_chain;

pub use app_attest::{
    verify_app_attest, AppAttestVerificationInput, VerifiedAppAttest, APP_ATTEST_FORMAT,
};
pub use errors::AttestationError;
pub use google_root::assert_play_integrity_root_is_production_ready;
pub use play_integrity::{
    verify_play_integrity, PlayIntegrityVerificationInput, VerifiedPlayIntegrity,
    MEETS_DEVICE_INTEGRITY, PLAY_RECOGNIZED,
};
pub use receipt_chain::{verify_mobile_receipt_chain, VerifiedMobileReceiptChain};
