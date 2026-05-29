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

/// Schema id for the eval-report receipt bundle.
pub const BUNDLE_SCHEMA_ID: &str = "chio.eval-report.bundle.v1";

/// Workspace path to the bundle schema.
pub const BUNDLE_SCHEMA_PATH: &str = "spec/eval/receipt-format.v1.json";
