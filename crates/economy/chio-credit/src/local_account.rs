//! In-memory `LocalCreditAccount` IOU mint path.
//!
//! Implements the credit evaluator hook against an in-memory account
//! that signs IOU envelopes with a [`SigningBackend`].
//! The mint rule is deterministic and pure over `(receipt, pricing_context)`:
//!
//! - The receipt's signature, content-addressed id, and action hash
//!   MUST verify against its embedded kernel key. Otherwise
//!   [`CreditEvaluatorError::SignatureInvalid`] is returned.
//! - Only semantically authorized receipts are eligible for minting. Deny,
//!   Cancelled, Incomplete, trace, and advisory receipts return `Ok(None)`.
//! - The price is read from the receipt's
//!   [`FinancialReceiptMetadata`]. If the metadata is absent or the
//!   `cost_charged` is zero, the result is `Ok(None)`. This is the
//!   manifest-price-zero / no-financial-metadata path (trace, advisory).
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
use crate::iou_v2::{
    mint_iou_envelope_v2, IouEnvelopeMintContextV2, IouEnvelopeReceiptTrustV2, IouEnvelopeV2Error,
    SignedIouEnvelopeV2,
};
use crate::obligation::{CreditAdmissionStore, CreditAdmissionStoreAdapter};
use crate::receipt::crypto_floor::ReceiptCryptoFloor;
use crate::receipt::{body::chio_receipt_id, body::ChioReceipt};

/// Deterministic IOU id derivation from the originating receipt id.
///
/// Using a SHA-256 of the receipt id keeps the IOU id stable across
/// re-evaluation, which a property test depends on.
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
    receipt_trust: IouEnvelopeReceiptTrustV2,
}

impl<B: SigningBackend> LocalCreditAccount<B> {
    /// Construct an account around an existing signing backend.
    ///
    /// This constructor has no trusted kernel signer set, so IOU minting
    /// fails closed until [`Self::new_with_trusted_kernel_keys`] is used.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            receipt_trust: IouEnvelopeReceiptTrustV2::new(
                std::iter::empty::<crate::crypto::PublicKey>(),
                ReceiptCryptoFloor::AllowClassical,
            ),
        }
    }

    /// Construct an account with an explicit trusted kernel signer set.
    /// When configured, IOU minting fails closed for receipts whose
    /// embedded kernel key is outside the set.
    pub fn new_with_trusted_kernel_keys<I>(backend: B, trusted_kernel_keys: I) -> Self
    where
        I: IntoIterator<Item = crate::crypto::PublicKey>,
    {
        Self {
            backend,
            receipt_trust: IouEnvelopeReceiptTrustV2::new(
                trusted_kernel_keys,
                ReceiptCryptoFloor::AllowClassical,
            ),
        }
    }

    #[must_use]
    pub fn new_with_receipt_trust(backend: B, receipt_trust: IouEnvelopeReceiptTrustV2) -> Self {
        Self {
            backend,
            receipt_trust,
        }
    }

    /// Borrow the underlying signing backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    #[must_use]
    pub const fn receipt_trust(&self) -> &IouEnvelopeReceiptTrustV2 {
        &self.receipt_trust
    }

    pub fn mint_obligation_iou_v2<S: CreditAdmissionStore>(
        &self,
        credit_admission_store: &CreditAdmissionStoreAdapter<S>,
        context: &IouEnvelopeMintContextV2<'_>,
    ) -> Result<SignedIouEnvelopeV2, IouEnvelopeV2Error> {
        mint_iou_envelope_v2(
            &self.backend,
            &self.receipt_trust,
            credit_admission_store,
            context,
        )
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
        let expected_receipt_id = chio_receipt_id(&receipt.body())
            .map_err(|err| CreditEvaluatorError::Canonical(err.to_string()))?;
        if expected_receipt_id != receipt.id {
            return Err(CreditEvaluatorError::SignatureInvalid {
                receipt_id: receipt.id.clone(),
            });
        }
        let parameter_hash_valid = receipt.action.verify_hash().map_err(|err| {
            CreditEvaluatorError::Canonical(format!(
                "receipt action hash verification raised: {err}"
            ))
        })?;
        if !parameter_hash_valid {
            return Err(CreditEvaluatorError::SignatureInvalid {
                receipt_id: receipt.id.clone(),
            });
        }
        let kernel_key = receipt.kernel_key.to_hex();
        if !self.receipt_trust.contains(&receipt.kernel_key) {
            return Err(CreditEvaluatorError::SignerUntrusted {
                receipt_id: receipt.id.clone(),
                kernel_key,
            });
        }

        // Only mediated/prevent allow receipts are eligible. Trace or
        // advisory observations use a non-mediated decision slot and
        // must never mint IOUs.
        if !receipt.is_allowed() {
            return Ok(None);
        }

        // Pricing context comes from the receipt's typed financial
        // metadata. Receipts without financial metadata (trace, advisory)
        // carry no manifest price and mint zero IOUs.
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
        body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
        economics::FinancialReceiptMetadata, economics::SettlementStatus, kinds::TrustLevel,
        metadata::GuardEvidence,
    };

    fn make_action() -> ToolCallAction {
        ToolCallAction::from_parameters(serde_json::json!({"path": "/tmp/x"})).unwrap()
    }

    fn make_signed_receipt(
        kp: &Keypair,
        decision: Decision,
        financial: Option<FinancialReceiptMetadata>,
    ) -> ChioReceipt {
        make_signed_receipt_with_action(kp, decision, financial, make_action())
    }

    fn make_signed_receipt_with_action(
        kp: &Keypair,
        decision: Decision,
        financial: Option<FinancialReceiptMetadata>,
        action: ToolCallAction,
    ) -> ChioReceipt {
        let metadata = financial.map(|fin| serde_json::json!({"financial": fin}));
        let body = ChioReceiptBody {
            id: "rcpt-iou-001".to_string(),
            timestamp: 1_710_000_000,
            capability_id: "cap-001".to_string(),
            tool_server: "srv-files".to_string(),
            tool_name: "file_read".to_string(),
            action,
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            decision: Some(decision),
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
            bbs_projection_version: None,
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
        let account = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp.clone()),
            [kp.public_key()],
        );
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
        let account = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp.clone()),
            [kp.public_key()],
        );
        let receipt = make_signed_receipt(&kp, Decision::Allow, None);
        assert!(account.evaluate(&receipt).unwrap().is_none());
    }

    #[test]
    fn allow_with_zero_cost_metadata_mints_zero_iou() {
        let kp = Keypair::generate();
        let account = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp.clone()),
            [kp.public_key()],
        );
        let mut financial = priced_metadata();
        financial.cost_charged = 0;
        let receipt = make_signed_receipt(&kp, Decision::Allow, Some(financial));
        assert!(account.evaluate(&receipt).unwrap().is_none());
    }

    #[test]
    fn deny_decision_mints_zero_iou_even_with_price() {
        let kp = Keypair::generate();
        let account = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp.clone()),
            [kp.public_key()],
        );
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
        let account = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp.clone()),
            [kp.public_key()],
        );
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
    fn mismatched_action_hash_returns_signature_invalid() {
        let kp = Keypair::generate();
        let account = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp.clone()),
            [kp.public_key()],
        );
        let mut action = make_action();
        action.parameters = serde_json::json!({"path": "/tmp/changed"});
        let receipt =
            make_signed_receipt_with_action(&kp, Decision::Allow, Some(priced_metadata()), action);

        match account.evaluate(&receipt) {
            Err(CreditEvaluatorError::SignatureInvalid { receipt_id }) => {
                assert_eq!(receipt_id, receipt.id);
            }
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn untrusted_kernel_key_returns_signer_untrusted() {
        let kp = Keypair::generate();
        let trusted = Keypair::generate();
        let account = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp.clone()),
            [trusted.public_key()],
        );
        let receipt = make_signed_receipt(&kp, Decision::Allow, Some(priced_metadata()));

        match account.evaluate(&receipt) {
            Err(CreditEvaluatorError::SignerUntrusted {
                receipt_id,
                kernel_key,
            }) => {
                assert_eq!(receipt_id, receipt.id);
                assert_eq!(kernel_key, kp.public_key().to_hex());
            }
            other => panic!("expected SignerUntrusted, got {other:?}"),
        }
    }

    #[test]
    fn iou_id_is_deterministic_across_re_evaluation() {
        let kp = Keypair::generate();
        let account = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp.clone()),
            [kp.public_key()],
        );
        let receipt = make_signed_receipt(&kp, Decision::Allow, Some(priced_metadata()));
        let first = account.evaluate(&receipt).unwrap().unwrap();
        let second = account.evaluate(&receipt).unwrap().unwrap();
        assert_eq!(first.body.iou_id, second.body.iou_id);
        assert_eq!(first.body, second.body);
    }
}
