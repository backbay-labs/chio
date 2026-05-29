//! SIEM event wrapper around ChioReceipt with extracted financial metadata.

use std::collections::BTreeSet;

use chio_core::chio_receipt_id;
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
    /// True when the receipt id, receipt signature, and action parameter hash verify.
    pub authoritative: bool,
    /// True when the embedded receipt signature verifies against the embedded kernel key.
    pub signature_valid: bool,
    /// True when the receipt id matches the canonical receipt body.
    pub receipt_id_valid: bool,
    /// True when the action parameter hash matches the canonical action parameters.
    pub parameter_hash_valid: bool,
    /// True when the receipt signer is pinned as a trusted kernel signer.
    pub signer_trusted: bool,
    /// True only for authoritative Chio-mediated allow receipts at a prevent boundary.
    pub authorized: bool,
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
        Self::from_receipt_with_trusted_kernel_keys(receipt, None)
    }

    /// Construct a SIEM event with an explicit trusted-kernel signer set.
    pub fn from_receipt_with_trusted_kernel_keys(
        receipt: ChioReceipt,
        trusted_kernel_keys: Option<&BTreeSet<String>>,
    ) -> Self {
        let semantics = receipt.semantic_fields();
        let receipt_kind = semantics.receipt_kind.as_str().to_string();
        let boundary_class = semantics.boundary_class.as_str().to_string();
        let receipt_id_valid = match chio_receipt_id(&receipt.body()) {
            Ok(expected) => expected == receipt.id,
            Err(_) => false,
        };
        let signature_valid = receipt.verify_signature().unwrap_or(false);
        let parameter_hash_valid = receipt.action.verify_hash().unwrap_or(false);
        let authoritative = receipt_id_valid && signature_valid && parameter_hash_valid;
        let signer_trusted = trusted_kernel_keys
            .map(|trusted| trusted.contains(&receipt.kernel_key.to_hex()))
            .unwrap_or(false);
        let authorized =
            authoritative && signer_trusted && semantics.is_authorized(receipt.decision.as_ref());
        let result = if authorized {
            "Authorized"
        } else if matches!(&receipt.decision, Some(chio_core::receipt::Decision::Allow))
            && semantics.is_authorized(receipt.decision.as_ref())
        {
            "Unverified"
        } else {
            semantics.result_label(receipt.decision.as_ref())
        }
        .to_string();
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
            authoritative,
            signature_valid,
            receipt_id_valid,
            parameter_hash_valid,
            signer_trusted,
            authorized,
            financial,
        }
    }

    /// True only for authoritative Chio-mediated allow receipts at a prevent boundary.
    #[must_use]
    pub fn is_authorized(&self) -> bool {
        self.authorized
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::crypto::Keypair;
    use chio_core::receipt::{ChioReceiptBody, Decision, ToolCallAction, TrustLevel};
    use chio_test_support::prelude::*;

    fn signed_allow_receipt() -> ChioReceipt {
        let keypair = Keypair::generate();
        ChioReceipt::sign(
            ChioReceiptBody {
                id: "siem-event-allow".to_string(),
                timestamp: 1_712_345_678,
                capability_id: "cap-siem".to_string(),
                tool_server: "srv-files".to_string(),
                tool_name: "file_read".to_string(),
                action: ToolCallAction::from_parameters(serde_json::json!({
                    "path": "/workspace/readme.md"
                }))
                .test_expect("action parameters serialize"),
                decision: Some(Decision::Allow),
                receipt_kind: chio_core::ReceiptKind::MediatedDecision,
                boundary_class: chio_core::BoundaryClass::Prevent,
                observation_outcome: None,
                tool_origin: chio_core::ToolOrigin::CallerExecuted,
                redaction_mode: chio_core::RedactionMode::None,
                actor_chain: Vec::new(),
                content_hash: "content-hash".to_string(),
                policy_hash: "policy-hash".to_string(),
                evidence: Vec::new(),
                metadata: None,
                trust_level: TrustLevel::Mediated,
                tenant_id: Some("tenant-a".to_string()),
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .test_expect("sign test receipt")
    }

    #[test]
    fn allow_receipt_requires_verified_id_signature_and_parameter_hash() {
        let receipt = signed_allow_receipt();
        let trusted = BTreeSet::from([receipt.kernel_key.to_hex()]);
        let event = SiemEvent::from_receipt_with_trusted_kernel_keys(receipt, Some(&trusted));

        assert!(event.receipt_id_valid);
        assert!(event.signature_valid);
        assert!(event.parameter_hash_valid);
        assert!(event.authoritative);
        assert!(event.authorized);
    }

    #[test]
    fn default_event_conversion_does_not_trust_self_signed_receipts() {
        let event = SiemEvent::from_receipt(signed_allow_receipt());

        assert!(event.receipt_id_valid);
        assert!(event.signature_valid);
        assert!(!event.signer_trusted);
        assert!(!event.authorized);
        assert_eq!(event.result, "Unverified");
    }

    #[test]
    fn tampered_allow_receipt_is_non_authoritative() {
        let mut receipt = signed_allow_receipt();
        receipt.id = "0000000000000000000000000000000000000000000000000000000000000000".to_string();

        let event = SiemEvent::from_receipt(receipt);

        assert!(!event.receipt_id_valid);
        assert!(!event.signature_valid);
        assert!(event.parameter_hash_valid);
        assert!(!event.authoritative);
        assert!(!event.authorized);
        assert_eq!(event.result, "Unverified");
    }
}
