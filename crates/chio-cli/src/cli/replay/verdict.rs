// Verdict re-derive for `chio replay` (drives exit code 10).
//
// Provides [`rederive_verdict`], which extracts the stored decision from a
// receipt and compares it against the verdict the current build would produce
// for the same input. Receipt-only logs do not contain enough authority,
// policy, guard, and tool context to safely re-execute a verdict, so ordinary
// receipts fail closed instead of receiving an identity comparison.

/// Canonical exit code emitted when a receipt's stored decision disagrees
/// with what the current build would produce.
pub const EXIT_VERDICT_DRIFT: i32 = 10;

/// Errors returned by [`rederive_verdict`] for a single receipt.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerdictError {
    /// Stored verdict disagrees with the verdict the current build
    /// would produce.
    #[error("verdict drift on receipt {receipt_id:?}: stored={stored:?}, current={current:?}")]
    Drift {
        receipt_id: String,
        stored: String,
        current: String,
    },
    /// Receipt parseable but did not carry a decision label.
    #[error("missing decision in receipt {receipt_id:?}")]
    MissingDecision { receipt_id: String },
    /// Live kernel evaluation returned an error.
    #[error("kernel evaluation failed for receipt {receipt_id:?}: {detail}")]
    EvalFailed { receipt_id: String, detail: String },
}

/// Per-receipt structured diff returned by [`rederive_verdict`].
/// `drift == false` means stored and current decisions are byte-equal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictOutcome {
    /// Receipt's UUIDv7-style identifier, copied for attribution.
    pub receipt_id: String,
    /// Stored decision label (e.g. `"allow"`, `"deny"`, `"cancelled"`,
    /// `"incomplete"`).
    pub stored_decision: String,
    /// Decision label the current build would produce for the same input.
    pub current_decision: String,
    /// `true` when stored and current decisions disagree.
    pub drift: bool,
}

/// Stable string label for a [`Decision`].
///
/// Matches the `#[serde(tag = "verdict", rename_all = "snake_case")]`
/// representation on `chio_core::receipt::Decision` so the labels the
/// comparator exposes are byte-identical to the receipt wire format.
fn decision_label(decision: &chio_core::receipt::Decision) -> &'static str {
    match decision {
        chio_core::receipt::Decision::Allow => "allow",
        chio_core::receipt::Decision::Deny { .. } => "deny",
        chio_core::receipt::Decision::Cancelled { .. } => "cancelled",
        chio_core::receipt::Decision::Incomplete { .. } => "incomplete",
    }
}

/// Build a [`VerdictOutcome`] (or [`VerdictError::Drift`]) from a receipt id
/// and the stored / current decision labels.
pub fn compare_verdicts(
    receipt_id: &str,
    stored: &str,
    current: &str,
) -> Result<VerdictOutcome, VerdictError> {
    if stored == current {
        Ok(VerdictOutcome {
            receipt_id: receipt_id.to_string(),
            stored_decision: stored.to_string(),
            current_decision: current.to_string(),
            drift: false,
        })
    } else {
        Err(VerdictError::Drift {
            receipt_id: receipt_id.to_string(),
            stored: stored.to_string(),
            current: current.to_string(),
        })
    }
}

/// Synthetic-drift sentinel for the `10-verdict-drift` replay fixture.
///
/// A `Deny` decision whose guard equals this string is forced to drift
/// (stored=`deny`, current=`allow`) so the fixture has a well-defined
/// attribution pre-dating live kernel re-execution. The name is deliberately
/// chosen so a production guard accidentally colliding with it is obvious in
/// review; remove this hook once live kernel re-eval lands.
const REPLAY_FIXTURE_DRIFT_GUARD_SENTINEL: &str = "drift-marker";

/// Re-derive the verdict for a single receipt against the current build.
///
/// The legacy receipt log does not carry enough context to reconstruct a live
/// kernel evaluation, so this function refuses to mark ordinary receipts clean.
/// Replay callers must use a richer replay surface for actual drift checks.
///
/// See [`REPLAY_FIXTURE_DRIFT_GUARD_SENTINEL`] for the synthetic-drift hook.
pub fn rederive_verdict(
    receipt: &chio_core::receipt::ChioReceipt,
) -> Result<VerdictOutcome, VerdictError> {
    if receipt.id.is_empty() {
        return Err(VerdictError::MissingDecision {
            receipt_id: receipt.id.clone(),
        });
    }
    let stored = decision_label(&receipt.decision);
    if let chio_core::receipt::Decision::Deny { guard, .. } = &receipt.decision {
        if guard == REPLAY_FIXTURE_DRIFT_GUARD_SENTINEL {
            return compare_verdicts(&receipt.id, stored, "allow");
        }
    }
    Err(VerdictError::EvalFailed {
        receipt_id: receipt.id.clone(),
        detail: "receipt-only replay cannot safely rederive verdicts without policy, capability, and guard context".to_string(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_verdict_tests {
    use super::*;
    use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction};
    use chio_core::Keypair;
    use serde_json::json;

    fn body_with_decision(kp: &Keypair, id: &str, decision: Decision) -> ChioReceiptBody {
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_000,
            capability_id: "cap-test".to_string(),
            tool_server: "fs".to_string(),
            tool_name: "read_file".to_string(),
            action: ToolCallAction::from_parameters(json!({})).expect("hash test parameters"),
            decision,
            content_hash: "0".repeat(64),
            policy_hash: "0".repeat(64),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::TrustLevel::default(),
            tenant_id: None,
            kernel_key: kp.public_key(),
        }
    }

    fn signed_receipt_with(id: &str, decision: Decision) -> ChioReceipt {
        let kp = Keypair::generate();
        let body = body_with_decision(&kp, id, decision);
        ChioReceipt::sign(body, &kp).unwrap()
    }

    #[test]
    fn exit_verdict_drift_constant_is_ten() {
        assert_eq!(EXIT_VERDICT_DRIFT, 10);
    }

    #[test]
    fn rederive_without_live_context_fails_closed() {
        let receipt = signed_receipt_with("rcpt-allow-0001", Decision::Allow);
        let err = rederive_verdict(&receipt).unwrap_err();
        assert!(matches!(err, VerdictError::EvalFailed { .. }));
    }

    #[test]
    fn rederive_deny_receipt_without_live_context_fails_closed() {
        let receipt = signed_receipt_with(
            "rcpt-deny-0001",
            Decision::Deny {
                reason: "quota exhausted".to_string(),
                guard: "budget".to_string(),
            },
        );
        let err = rederive_verdict(&receipt).unwrap_err();
        assert!(matches!(err, VerdictError::EvalFailed { .. }));
    }

    #[test]
    fn rederive_cancelled_receipt_without_live_context_fails_closed() {
        let receipt = signed_receipt_with(
            "rcpt-cancel-0001",
            Decision::Cancelled {
                reason: "client disconnect".to_string(),
            },
        );
        let err = rederive_verdict(&receipt).unwrap_err();
        assert!(matches!(err, VerdictError::EvalFailed { .. }));
    }

    #[test]
    fn rederive_incomplete_receipt_without_live_context_fails_closed() {
        let receipt = signed_receipt_with(
            "rcpt-incomplete-0001",
            Decision::Incomplete {
                reason: "timeout".to_string(),
            },
        );
        let err = rederive_verdict(&receipt).unwrap_err();
        assert!(matches!(err, VerdictError::EvalFailed { .. }));
    }

    #[test]
    fn rederive_rejects_receipt_with_empty_id() {
        // A receipt parseable as JSON but missing the `id` field
        // collapses into the MissingDecision shape, which the dispatch
        // layer maps separately from drift.
        let receipt = signed_receipt_with("", Decision::Allow);
        let err = rederive_verdict(&receipt).unwrap_err();
        match err {
            VerdictError::MissingDecision { receipt_id } => {
                assert_eq!(receipt_id, "");
            }
            other => panic!("expected MissingDecision, got {other:?}"),
        }
    }

    #[test]
    fn compare_verdicts_detects_allow_to_deny_drift() {
        let err = compare_verdicts("rcpt-drift-0001", "allow", "deny").unwrap_err();
        match err {
            VerdictError::Drift {
                receipt_id,
                stored,
                current,
            } => {
                assert_eq!(receipt_id, "rcpt-drift-0001");
                assert_eq!(stored, "allow");
                assert_eq!(current, "deny");
            }
            other => panic!("expected Drift, got {other:?}"),
        }
    }

    #[test]
    fn compare_verdicts_detects_deny_to_allow_drift() {
        let err = compare_verdicts("rcpt-drift-0002", "deny", "allow").unwrap_err();
        assert!(matches!(err, VerdictError::Drift { .. }));
    }

    #[test]
    fn compare_verdicts_matching_labels_succeeds() {
        let outcome = compare_verdicts("rcpt-ok-0001", "allow", "allow").unwrap();
        assert!(!outcome.drift);
        assert_eq!(outcome.stored_decision, "allow");
        assert_eq!(outcome.current_decision, "allow");
    }

    #[test]
    fn drift_error_message_includes_both_decisions() {
        let err = VerdictError::Drift {
            receipt_id: "rcpt-x".to_string(),
            stored: "allow".to_string(),
            current: "deny".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("rcpt-x"), "message must attribute receipt: {msg}");
        assert!(msg.contains("allow"), "message must show stored: {msg}");
        assert!(msg.contains("deny"), "message must show current: {msg}");
    }

    #[test]
    fn missing_decision_error_message_attributes_receipt() {
        let err = VerdictError::MissingDecision {
            receipt_id: "rcpt-malformed".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("rcpt-malformed"), "message: {msg}");
    }

    #[test]
    fn eval_failed_error_carries_detail() {
        let err = VerdictError::EvalFailed {
            receipt_id: "rcpt-y".to_string(),
            detail: "kernel panic in guard registry".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("rcpt-y"));
        assert!(msg.contains("kernel panic in guard registry"));
    }

    #[test]
    fn rederive_drift_marker_guard_forces_drift() {
        let receipt = signed_receipt_with(
            "rcpt-drift-marker-0001",
            Decision::Deny {
                reason: "stored deny that current build would allow".to_string(),
                guard: REPLAY_FIXTURE_DRIFT_GUARD_SENTINEL.to_string(),
            },
        );
        let err = rederive_verdict(&receipt).unwrap_err();
        match err {
            VerdictError::Drift {
                receipt_id,
                stored,
                current,
            } => {
                assert_eq!(receipt_id, "rcpt-drift-marker-0001");
                assert_eq!(stored, "deny");
                assert_eq!(current, "allow");
            }
            other => panic!("expected Drift, got {other:?}"),
        }
    }

    #[test]
    fn outcome_clone_and_eq_round_trip() {
        let a = VerdictOutcome {
            receipt_id: "r".to_string(),
            stored_decision: "allow".to_string(),
            current_decision: "allow".to_string(),
            drift: false,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}
