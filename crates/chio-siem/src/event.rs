//! SIEM event wrapper around ChioReceipt with extracted financial metadata.

use chio_core::receipt::{ChioReceipt, FinancialReceiptMetadata};
use serde::{Deserialize, Serialize};

/// A SIEM event wrapping a ChioReceipt with optionally extracted financial metadata.
///
/// The `receipt` field contains the full receipt (including raw metadata) for
/// forwarding to SIEM backends. The `financial` field is extracted for
/// structured filtering without requiring JSON path traversal on the export side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemEvent {
    /// The full ChioReceipt as stored in the kernel receipt database.
    pub receipt: ChioReceipt,
    /// Semantic receipt class used to prevent trace/advisory observations from
    /// being rendered as authorization decisions.
    pub receipt_kind: String,
    /// Runtime mediation boundary for this receipt.
    pub boundary_class: String,
    /// Human-facing semantic result label.
    pub result: String,
    /// Financial metadata extracted from `receipt.metadata["financial"]`, if present.
    pub financial: Option<FinancialReceiptMetadata>,
}

impl SiemEvent {
    /// Construct a SiemEvent from a ChioReceipt.
    ///
    /// Attempts to extract `FinancialReceiptMetadata` from
    /// `receipt.metadata["financial"]`. Returns `None` for the `financial` field
    /// if the metadata key is absent or fails to deserialize.
    pub fn from_receipt(receipt: ChioReceipt) -> Self {
        let semantics = receipt.semantic_fields();
        let receipt_kind = semantics.receipt_kind.as_str().to_string();
        let boundary_class = semantics.boundary_class.as_str().to_string();
        let result = semantics.result_label(&receipt.decision).to_string();
        let financial = receipt
            .metadata
            .as_ref()
            .and_then(|meta| meta.get("financial"))
            .and_then(|val| serde_json::from_value::<FinancialReceiptMetadata>(val.clone()).ok());

        Self {
            receipt,
            receipt_kind,
            boundary_class,
            result,
            financial,
        }
    }

    /// True only for authoritative Chio-mediated allow receipts at a prevent boundary.
    #[must_use]
    pub fn is_authorized(&self) -> bool {
        self.receipt
            .semantic_fields()
            .is_authorized(&self.receipt.decision)
    }
}
