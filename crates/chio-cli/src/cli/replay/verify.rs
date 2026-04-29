// Receipt signature re-verifier for `chio replay`.
//
// Provides [`verify_receipt`]: verifies the embedded Ed25519 signature on a
// receipt against its `kernel_key`. Called once per receipt from the log
// reader. `ok == false` drives exit code 20.

/// Canonical exit code emitted when any receipt fails signature
/// re-verification.
pub const EXIT_BAD_SIGNATURE: i32 = 20;

/// Per-receipt outcome from [`verify_receipt`].
///
/// `ok == true`: signature verified. `ok == false` with `signer_key_hex`
/// present: verification failed. `ok == false` with `signer_key_hex == ""`:
/// receipt could not be deserialized (maps to exit 30, not 20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyOutcome {
    /// Whether the embedded signature verified against the embedded
    /// `kernel_key`. `false` means signature mismatch, kernel-side
    /// verifier error, or that the receipt could not be parsed in the
    /// first place; consult `error` and `signer_key_hex` to disambiguate.
    pub ok: bool,
    /// Lowercase hex of the receipt's `kernel_key`. Empty when the input
    /// could not be parsed as a `ChioReceipt`.
    pub signer_key_hex: String,
    /// Human-readable failure detail. `None` only when `ok == true`.
    pub error: Option<String>,
}

/// Re-verify the embedded signature on a single receipt.
///
/// Never returns `Err`; all failure modes are captured in [`VerifyOutcome`]
/// so callers can drive exit-code policy off the outcome shape.
pub fn verify_receipt(
    value: &serde_json::Value,
    trusted_kernel_key: Option<&chio_core::PublicKey>,
) -> VerifyOutcome {
    let receipt: chio_core::receipt::ChioReceipt = match serde_json::from_value(value.clone()) {
        Ok(r) => r,
        Err(error) => {
            return VerifyOutcome {
                ok: false,
                signer_key_hex: String::new(),
                error: Some(format!("malformed receipt JSON: {error}")),
            };
        }
    };

    let signer_key_hex = receipt.kernel_key.to_hex();

    if trusted_kernel_key.is_none_or(|trusted| trusted != &receipt.kernel_key) {
        return VerifyOutcome {
            ok: false,
            signer_key_hex,
            error: Some("receipt signer is not in the trusted kernel key pin set".to_string()),
        };
    }

    match receipt.action.verify_hash() {
        Ok(true) => {}
        Ok(false) => {
            return VerifyOutcome {
                ok: false,
                signer_key_hex,
                error: Some("action parameter_hash does not match canonical parameters".to_string()),
            };
        }
        Err(error) => {
            return VerifyOutcome {
                ok: false,
                signer_key_hex,
                error: Some(format!("action parameter_hash verifier error: {error}")),
            };
        }
    }

    match receipt.verify_signature() {
        Ok(true) => VerifyOutcome {
            ok: true,
            signer_key_hex,
            error: None,
        },
        Ok(false) => VerifyOutcome {
            ok: false,
            signer_key_hex,
            error: Some("signature mismatch".to_string()),
        },
        Err(error) => VerifyOutcome {
            ok: false,
            signer_key_hex,
            error: Some(format!("verifier error: {error}")),
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_verify_tests {
    use super::*;
    use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction};
    use chio_core::Keypair;
    use serde_json::json;

    fn sample_body(kp: &Keypair) -> ChioReceiptBody {
        ChioReceiptBody {
            id: "rcpt-test-0001".to_string(),
            timestamp: 1_700_000_000,
            capability_id: "cap-test".to_string(),
            tool_server: "fs".to_string(),
            tool_name: "read_file".to_string(),
            action: ToolCallAction::from_parameters(json!({})).unwrap(),
            decision: Decision::Allow,
            content_hash: "0".repeat(64),
            policy_hash: "0".repeat(64),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::TrustLevel::default(),
            tenant_id: None,
            kernel_key: kp.public_key(),
        }
    }

    fn signed_receipt() -> ChioReceipt {
        let kp = Keypair::generate();
        let body = sample_body(&kp);
        ChioReceipt::sign(body, &kp).unwrap()
    }

    #[test]
    fn verify_receipt_accepts_good_signature() {
        let receipt = signed_receipt();
        let value = serde_json::to_value(&receipt).unwrap();

        let outcome = verify_receipt(&value, Some(&receipt.kernel_key));
        assert!(outcome.ok, "good signature must verify: {outcome:?}");
        assert!(outcome.error.is_none(), "no error for good signature");
        assert_eq!(outcome.signer_key_hex.len(), 64, "ed25519 key is 32 bytes");
    }

    #[test]
    fn verify_receipt_rejects_tampered_signature() {
        let receipt = signed_receipt();
        let mut value = serde_json::to_value(&receipt).unwrap();
        // Flip a byte in the canonical content_hash so the signed body
        // no longer matches the signature. The kernel_key field is left
        // untouched so the function can still attribute the failure.
        value["content_hash"] = json!("ff".repeat(32));

        let outcome = verify_receipt(&value, Some(&receipt.kernel_key));
        assert!(!outcome.ok, "tampered receipt must not verify");
        assert!(outcome.error.is_some(), "bad signature carries an error note");
        assert_eq!(
            outcome.signer_key_hex.len(),
            64,
            "signer key still attributed on bad signature",
        );
    }

    #[test]
    fn verify_receipt_rejects_malformed_json() {
        // A bare object with none of the required ChioReceipt fields.
        // serde_json::from_value should fail before any signature check.
        let value = json!({"id": "no-signature-here"});

        let outcome = verify_receipt(&value, None);
        assert!(!outcome.ok, "malformed JSON must not verify");
        assert_eq!(
            outcome.signer_key_hex, "",
            "signer_key_hex empty when receipt cannot be parsed",
        );
        let error = outcome.error.expect("malformed JSON carries an error");
        assert!(
            error.contains("malformed receipt JSON"),
            "error must explain the parse failure, got: {error}",
        );
    }

    #[test]
    fn exit_bad_signature_constant_is_twenty() {
        assert_eq!(EXIT_BAD_SIGNATURE, 20);
    }

    #[test]
    fn verify_receipt_rejects_unpinned_signer() {
        let receipt = signed_receipt();
        let other = Keypair::generate();
        let value = serde_json::to_value(&receipt).unwrap();

        let outcome = verify_receipt(&value, Some(&other.public_key()));
        assert!(!outcome.ok, "unpinned signer must not verify");
        assert!(outcome
            .error
            .unwrap()
            .contains("not in the trusted kernel key"));
    }

    #[test]
    fn verify_receipt_rejects_mismatched_parameter_hash() {
        let kp = Keypair::generate();
        let mut body = sample_body(&kp);
        body.action.parameter_hash = "0".repeat(64);
        let resigned = ChioReceipt::sign(body, &kp).unwrap();
        let value = serde_json::to_value(&resigned).unwrap();

        let outcome = verify_receipt(&value, Some(&resigned.kernel_key));
        assert!(!outcome.ok, "mismatched parameter hash must not verify");
        assert!(outcome.error.unwrap().contains("parameter_hash"));
    }
}
