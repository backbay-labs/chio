// Raw-`serde_json::Value` gates for `chio replay <log>`.
//
// These two helpers run BEFORE `serde_json::from_value::<ChioReceipt>` so
// future-versioned receipts and unsupported redaction passes can be
// attributed to their canonical exit codes (40 / 50) rather than collapsing
// into the generic parse-error shape (30).

/// Receipt schema identifier this build supports.
pub const SUPPORTED_RECEIPT_SCHEMA: &str = "chio.receipt/v1";

/// Redaction-pass identifier this build can replay against receipts.
/// Mirrors `replay/validate.rs::SUPPORTED_REDACTION_PASS_ID` (frame side).
pub const SUPPORTED_RECEIPT_REDACTION_PASS_ID: &str = "m06-redactors@1.4.0+default";

/// Failure shape from the raw-Value gate helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptGateError {
    /// `schema_version` is present and is not [`SUPPORTED_RECEIPT_SCHEMA`].
    SchemaMismatch { observed: String },
    /// `metadata.redaction_pass_id` is present and is not the supported id.
    RedactionMismatch { observed: String },
}

/// Reject any value that carries a `schema_version` other than
/// [`SUPPORTED_RECEIPT_SCHEMA`].
///
/// Receipts that omit `schema_version` (the canonical wire shape for
/// `chio.receipt/v1`) are accepted: forward-compat is the only purpose of
/// this gate, so the absence of the marker is not by itself a divergence.
pub fn check_receipt_schema(value: &serde_json::Value) -> Result<(), ReceiptGateError> {
    let Some(version) = value.get("schema_version") else {
        return Ok(());
    };
    let observed = version.as_str().unwrap_or("").to_string();
    if observed == SUPPORTED_RECEIPT_SCHEMA {
        return Ok(());
    }
    Err(ReceiptGateError::SchemaMismatch { observed })
}

/// Reject any value whose `metadata.redaction_pass_id` is not
/// [`SUPPORTED_RECEIPT_REDACTION_PASS_ID`].
///
/// Receipts with no `metadata` or no `metadata.redaction_pass_id` are
/// accepted (the gate fires only when an unsupported id is asserted).
pub fn check_receipt_redaction(value: &serde_json::Value) -> Result<(), ReceiptGateError> {
    let Some(metadata) = value.get("metadata") else {
        return Ok(());
    };
    let Some(pass_id) = metadata.get("redaction_pass_id") else {
        return Ok(());
    };
    let observed = pass_id.as_str().unwrap_or("").to_string();
    if observed == SUPPORTED_RECEIPT_REDACTION_PASS_ID {
        return Ok(());
    }
    Err(ReceiptGateError::RedactionMismatch { observed })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_schema_gate_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn schema_gate_accepts_value_without_schema_version() {
        let value = json!({"id": "rcpt-1"});
        check_receipt_schema(&value).unwrap();
    }

    #[test]
    fn schema_gate_accepts_canonical_schema_version() {
        let value = json!({"schema_version": SUPPORTED_RECEIPT_SCHEMA});
        check_receipt_schema(&value).unwrap();
    }

    #[test]
    fn schema_gate_rejects_unknown_schema_version() {
        let value = json!({"schema_version": "chio.receipt/v999"});
        let err = check_receipt_schema(&value).unwrap_err();
        match err {
            ReceiptGateError::SchemaMismatch { observed } => {
                assert_eq!(observed, "chio.receipt/v999");
            }
            other => panic!("expected SchemaMismatch, got {other:?}"),
        }
    }

    #[test]
    fn redaction_gate_accepts_value_without_metadata() {
        let value = json!({"id": "rcpt-1"});
        check_receipt_redaction(&value).unwrap();
    }

    #[test]
    fn redaction_gate_accepts_value_without_pass_id() {
        let value = json!({"metadata": {"foo": "bar"}});
        check_receipt_redaction(&value).unwrap();
    }

    #[test]
    fn redaction_gate_accepts_supported_pass_id() {
        let value = json!({
            "metadata": {"redaction_pass_id": SUPPORTED_RECEIPT_REDACTION_PASS_ID},
        });
        check_receipt_redaction(&value).unwrap();
    }

    #[test]
    fn redaction_gate_rejects_unsupported_pass_id() {
        let value = json!({
            "metadata": {"redaction_pass_id": "redaction-pass-not-resolvable-by-current-build"},
        });
        let err = check_receipt_redaction(&value).unwrap_err();
        match err {
            ReceiptGateError::RedactionMismatch { observed } => {
                assert_eq!(observed, "redaction-pass-not-resolvable-by-current-build");
            }
            other => panic!("expected RedactionMismatch, got {other:?}"),
        }
    }
}
