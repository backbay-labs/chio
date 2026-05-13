//! In-memory `LocalCreditAccount` IOU mint path.
//!
//! M09 P1.T2 implements the credit evaluator hook against an
//! in-memory account that signs IOU envelopes with a [`SigningBackend`].
//! The mint rule is deterministic and pure over `(receipt, pricing_context)`:
//!
//! - The receipt's signature MUST verify against its embedded kernel
//!   key. Otherwise [`CreditEvaluatorError::SignatureInvalid`] is
//!   returned.
//! - Only semantically authorized receipts are eligible for minting. Deny,
//!   Cancelled, Incomplete, trace, and advisory receipts return `Ok(None)`.
//! - The price is read from the receipt's
//!   [`FinancialReceiptMetadata`]. If the metadata is absent or the
//!   `cost_charged` is zero, the result is `Ok(None)`. This is the
//!   manifest-price-zero / legacy-receipt fallback.
//! - When all preconditions hold, exactly one [`IouEnvelope`] is
//!   produced. The envelope `iou_id` is derived deterministically
//!   from `receipt_id` so re-evaluating the same receipt yields a
//!   byte-identical envelope.
//!
//! The receipt is never mutated; the mint path is read-only over
//! its inputs.

use crate::crypto::{sha256_hex, sign_canonical_with_backend, SigningBackend};
use crate::hook::{
    CreditEvaluatorError, CreditEvaluatorHook, IouEnvelope, IouEnvelopeBody, IOU_ENVELOPE_SCHEMA,
};
use crate::receipt::ChioReceipt;

/// Deterministic IOU id derivation from the originating receipt id.
///
/// Using a SHA-256 of the receipt id keeps the IOU id stable across
/// re-evaluation, which the property test in P1.T4 depends on.
fn derive_iou_id(receipt_id: &str) -> String {
    format!("iou-{}", &sha256_hex(receipt_id.as_bytes())[..32])
}

/// In-memory credit account that mints IOUs against finalized
/// receipts.
///
/// Holds a [`SigningBackend`] used to sign IOU bodies. The signing
/// identity becomes the `issuer_key` carried by every minted IOU
/// envelope.
pub struct LocalCreditAccount<B: SigningBackend> {
    backend: B,
}

impl<B: SigningBackend> LocalCreditAccount<B> {
    /// Construct an account around an existing signing backend. The
    /// backend's public key is recorded as the issuer on every
    /// IOU minted by this account.
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Borrow the underlying signing backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }
}

impl<B: SigningBackend> CreditEvaluatorHook for LocalCreditAccount<B> {
    fn evaluate(&self, receipt: &ChioReceipt) -> Result<Option<IouEnvelope>, CreditEvaluatorError> {
        // Fail-closed signature gate. An unsigned or tampered receipt
        // mints nothing.
        let verified = receipt.verify_signature().map_err(|err| {
            CreditEvaluatorError::Canonical(format!("receipt signature verification raised: {err}"))
        })?;
        if !verified {
            return Err(CreditEvaluatorError::SignatureInvalid {
                receipt_id: receipt.id.clone(),
            });
        }

        // Only mediated/prevent allow receipts are eligible. Trace or
        // advisory observations may preserve a legacy-shaped decision slot,
        // but they must never mint IOUs.
        if !receipt.is_allowed() {
            return Ok(None);
        }

        // Pricing context comes from the receipt's typed financial
        // metadata. Receipts without financial metadata are legacy
        // (no manifest price) and mint zero IOUs.
        let Some(financial) = receipt.financial_metadata() else {
            return Ok(None);
        };
        if financial.cost_charged == 0 {
            return Ok(None);
        }

        let body = IouEnvelopeBody {
            schema: IOU_ENVELOPE_SCHEMA.to_string(),
            iou_id: derive_iou_id(&receipt.id),
            receipt_id: receipt.id.clone(),
            receipt_timestamp: receipt.timestamp,
            tenant_id: receipt.tenant_id.clone(),
            tool_server: receipt.tool_server.clone(),
            tool_name: receipt.tool_name.clone(),
            capability_id: receipt.capability_id.clone(),
            amount_units: financial.cost_charged,
            currency: financial.currency.clone(),
            issuer_key: self.backend.public_key(),
        };

        let (signature, _bytes) = sign_canonical_with_backend(&self.backend, &body)
            .map_err(|err| CreditEvaluatorError::Signing(err.to_string()))?;

        Ok(Some(IouEnvelope {
            body,
            algorithm: Some(self.backend.algorithm()),
            signature,
        }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::{sha256_hex, Ed25519Backend, Keypair};
    use crate::receipt::{
        ChioReceipt, ChioReceiptBody, Decision, FinancialReceiptMetadata, GuardEvidence,
        SettlementStatus, ToolCallAction, TrustLevel,
    };

    fn make_action() -> ToolCallAction {
        ToolCallAction::from_parameters(serde_json::json!({"path": "/tmp/x"})).unwrap()
    }

    fn make_signed_receipt(
        kp: &Keypair,
        decision: Decision,
        financial: Option<FinancialReceiptMetadata>,
    ) -> ChioReceipt {
        let metadata = financial.map(|fin| serde_json::json!({"financial": fin}));
        let body = ChioReceiptBody {
            id: "rcpt-iou-001".to_string(),
            timestamp: 1_710_000_000,
            capability_id: "cap-001".to_string(),
            tool_server: "srv-files".to_string(),
            tool_name: "file_read".to_string(),
            action: make_action(),
            decision,
            content_hash: sha256_hex(br#"{"ok":true}"#),
            policy_hash: "abc123def456".to_string(),
            evidence: vec![GuardEvidence {
                guard_name: "ForbiddenPathGuard".to_string(),
                verdict: true,
                details: None,
            }],
            metadata,
            trust_level: TrustLevel::default(),
            tenant_id: Some("tenant-a".to_string()),
            kernel_key: kp.public_key(),
        };
        ChioReceipt::sign(body, kp).unwrap()
    }

    fn priced_metadata() -> FinancialReceiptMetadata {
        FinancialReceiptMetadata {
            grant_index: 0,
            cost_charged: 250,
            currency: "USD".to_string(),
            budget_remaining: 750,
            budget_total: 1000,
            delegation_depth: 1,
            root_budget_holder: "tenant-a".to_string(),
            payment_reference: None,
            settlement_status: SettlementStatus::Pending,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: None,
        }
    }

    #[test]
    fn allow_with_priced_metadata_mints_one_iou() {
        let kp = Keypair::generate();
        let account = LocalCreditAccount::new(Ed25519Backend::new(kp.clone()));
        let receipt = make_signed_receipt(&kp, Decision::Allow, Some(priced_metadata()));
        let envelope = account
            .evaluate(&receipt)
            .unwrap()
            .expect("priced allow receipt mints one IOU");
        assert_eq!(envelope.body.amount_units, 250);
        assert_eq!(envelope.body.currency, "USD");
        assert_eq!(envelope.body.receipt_id, receipt.id);
        assert_eq!(envelope.body.tenant_id.as_deref(), Some("tenant-a"));
        assert!(envelope.verify_signature().unwrap());
    }

    #[test]
    fn allow_without_financial_metadata_mints_zero_iou() {
        let kp = Keypair::generate();
        let account = LocalCreditAccount::new(Ed25519Backend::new(kp.clone()));
        let receipt = make_signed_receipt(&kp, Decision::Allow, None);
        assert!(account.evaluate(&receipt).unwrap().is_none());
    }

    #[test]
    fn allow_with_zero_cost_metadata_mints_zero_iou() {
        let kp = Keypair::generate();
        let account = LocalCreditAccount::new(Ed25519Backend::new(kp.clone()));
        let mut financial = priced_metadata();
        financial.cost_charged = 0;
        let receipt = make_signed_receipt(&kp, Decision::Allow, Some(financial));
        assert!(account.evaluate(&receipt).unwrap().is_none());
    }

    #[test]
    fn deny_decision_mints_zero_iou_even_with_price() {
        let kp = Keypair::generate();
        let account = LocalCreditAccount::new(Ed25519Backend::new(kp.clone()));
        let receipt = make_signed_receipt(
            &kp,
            Decision::Deny {
                reason: "blocked".to_string(),
                guard: "ForbiddenPathGuard".to_string(),
            },
            Some(priced_metadata()),
        );
        assert!(account.evaluate(&receipt).unwrap().is_none());
    }

    #[test]
    fn tampered_signature_returns_signature_invalid() {
        let kp = Keypair::generate();
        let account = LocalCreditAccount::new(Ed25519Backend::new(kp.clone()));
        let mut receipt = make_signed_receipt(&kp, Decision::Allow, Some(priced_metadata()));
        // Mutate a signed field to invalidate the signature.
        receipt.tool_name = "file_write".to_string();
        match account.evaluate(&receipt) {
            Err(CreditEvaluatorError::SignatureInvalid { receipt_id }) => {
                assert_eq!(receipt_id, receipt.id);
            }
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn iou_id_is_deterministic_across_re_evaluation() {
        let kp = Keypair::generate();
        let account = LocalCreditAccount::new(Ed25519Backend::new(kp.clone()));
        let receipt = make_signed_receipt(&kp, Decision::Allow, Some(priced_metadata()));
        let first = account.evaluate(&receipt).unwrap().unwrap();
        let second = account.evaluate(&receipt).unwrap().unwrap();
        assert_eq!(first.body.iou_id, second.body.iou_id);
        assert_eq!(first.body, second.body);
    }
}
