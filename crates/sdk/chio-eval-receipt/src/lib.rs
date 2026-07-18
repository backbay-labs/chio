//! Reference verifier for `chio.eval-report.bundle.v1` receipt bundles.
//!
//! The crate verifies eval-report receipt bundles end to end: it validates the
//! bundle envelope, recomputes the corpus SHA-256, and checks the detached
//! memo signatures attached to each receipt, failing closed on any mismatch.
//! It also exports scenario runs into the bundle format and exposes a CLI for
//! verifying bundles and memo signatures from the command line.
//!
//! The two entry points are [`verify_bundle`] (and [`verify_fixture_bundle`]),
//! which parse and verify a bundle JSON document into a [`VerifiedBundle`], and
//! [`export_scenario_run`], which builds a [`Bundle`] from scenario inputs.

#![forbid(unsafe_code)]

pub mod export;
pub mod verify;

pub use export::{
    export_scenario_run, Bundle, Corpus, EvalRunMeta, EvalRunMetaParts, ExportError, Producer,
    Receipt, ReceiptEntry, ReceiptEvidence, ReceiptParts, VERDICT_MATRIX_CORPUS_SHA256,
    VERDICT_MATRIX_MANIFEST_PATH, VERDICT_MATRIX_SCENARIO_COUNT,
};
pub use verify::{
    test_signature_for_bundle_json, verify_bundle, verify_fixture_bundle, BundleError,
    VerifiedBundle,
};

pub use chio_core_types::receipt::authoritative_spend::{
    is_authoritative_spend_receipt, receipt_meets_guarantee_floor, BudgetAuthorityReceiptRef,
    NotAuthoritativeReason, PresentedNonceView, MEDIATED_SPEND_PROFILE,
};

/// Schema id for the eval-report receipt bundle.
pub const BUNDLE_SCHEMA_ID: &str = "chio.eval-report.bundle.v1";

/// Workspace path to the bundle schema.
pub const BUNDLE_SCHEMA_PATH: &str = "spec/eval/receipt-format.v1.json";

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod contract_freeze {
    #[test]
    fn mediated_spend_profile_is_frozen() {
        assert_eq!(super::MEDIATED_SPEND_PROFILE, "chio.mediated_spend.v1");
    }

    #[test]
    fn adr_0016_and_protocol_document_the_profile() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../..");
        let adr = std::fs::read_to_string(format!(
            "{root}/docs/adr/ADR-0016-authoritative-spend-contract.md"
        ))
        .expect("ADR-0016 must exist");
        assert!(adr.contains("chio.mediated_spend.v1"));
        assert!(adr.contains("chio.execution_nonce.v1"));
        assert!(adr.contains("quote.quoted_cost"));
        assert!(adr.contains("execution_nonce_ref"));
        assert!(adr.contains("hold_ref"));
        let protocol = std::fs::read_to_string(format!("{root}/spec/PROTOCOL.md"))
            .expect("PROTOCOL.md must exist");
        assert!(protocol.contains("chio.mediated_spend.v1"));
    }
}
