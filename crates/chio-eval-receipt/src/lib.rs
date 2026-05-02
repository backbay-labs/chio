//! Placeholder surface for eval-report receipt bundle verification.
//!
//! M02.P0 establishes the crate and public constants so downstream P2/P3
//! tickets can add export, schema, and signature verification without moving
//! the workspace boundary again. Until the verifier lands, callers receive a
//! fail-closed readiness result.

#![forbid(unsafe_code)]

pub mod export;
pub mod verify;

pub use export::{
    export_scenario_run, Bundle, Corpus, EvalRunMeta, EvalRunMetaParts, ExportError, Producer,
    Receipt, ReceiptEntry, ReceiptEvidence, ReceiptParts, VERDICT_MATRIX_CORPUS_SHA256,
    VERDICT_MATRIX_MANIFEST_PATH, VERDICT_MATRIX_SCENARIO_COUNT,
};
pub use verify::{test_signature_for_bundle_json, verify_bundle, BundleError, VerifiedBundle};

/// Schema id reserved for the eval-report receipt bundle.
pub const BUNDLE_SCHEMA_ID: &str = "chio.eval-report.bundle.v1";

/// Planned schema path for the bundle format.
pub const BUNDLE_SCHEMA_PATH: &str = "spec/eval/receipt-format.v1.json";

/// Partner contracted at M02.P0 for the initial evaluation beachhead.
pub const P0_PARTNER: &str = "METR";

/// Stable P0 descriptor for audit and downstream implementation checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvalReceiptSurface {
    /// Schema id the verifier will enforce.
    pub schema_id: &'static str,
    /// Workspace path where the schema will be published.
    pub schema_path: &'static str,
    /// Partner selected for the P0 integration lane.
    pub partner: &'static str,
    /// Current implementation stage.
    pub stage: &'static str,
}

impl EvalReceiptSurface {
    /// Return the P0 placeholder descriptor.
    pub const fn p0_placeholder() -> Self {
        Self {
            schema_id: BUNDLE_SCHEMA_ID,
            schema_path: BUNDLE_SCHEMA_PATH,
            partner: P0_PARTNER,
            stage: "p0-placeholder",
        }
    }

    /// Return the P3 verifier descriptor.
    pub const fn p3_verifier() -> Self {
        Self {
            schema_id: BUNDLE_SCHEMA_ID,
            schema_path: BUNDLE_SCHEMA_PATH,
            partner: P0_PARTNER,
            stage: "p3-verifier",
        }
    }

    /// Fail closed until P3 lands verifier implementation.
    pub fn verifier_ready(&self) -> bool {
        matches!(self.stage, "p3-verifier")
    }
}

/// Return the current eval-receipt verifier surface descriptor.
pub const fn surface() -> EvalReceiptSurface {
    EvalReceiptSurface::p3_verifier()
}

#[cfg(test)]
mod tests {
    use super::{surface, BUNDLE_SCHEMA_ID, BUNDLE_SCHEMA_PATH, P0_PARTNER};

    #[test]
    fn placeholder_surface_is_pinned() {
        let surface = surface();
        assert_eq!(surface.schema_id, BUNDLE_SCHEMA_ID);
        assert_eq!(surface.schema_path, BUNDLE_SCHEMA_PATH);
        assert_eq!(surface.partner, P0_PARTNER);
        assert_eq!(surface.stage, "p3-verifier");
        assert!(surface.verifier_ready());
    }
}
