use chio_transaction_passport::TransactionPassportError;

use super::super::evidence::validate_sha256_hex;
use super::{claim_failed, required_json_str, required_json_u64, AgentWebProofEnvelope};

pub(super) fn validate_subject(
    value: &serde_json::Value,
    envelope: &AgentWebProofEnvelope,
) -> Result<(), TransactionPassportError> {
    for (field, message) in [
        (
            "delegated_payment_token_digest",
            "missing ACP-Commerce delegated payment token digest",
        ),
        (
            "checkout_context_digest",
            "missing ACP-Commerce checkout context digest",
        ),
        (
            "order_context_digest",
            "missing ACP-Commerce order context digest",
        ),
        (
            "payment_instruction_digest",
            "missing ACP-Commerce payment instruction digest",
        ),
        (
            "merchant_identity_digest",
            "missing ACP-Commerce merchant identity digest",
        ),
        (
            "buyer_identity_digest",
            "missing ACP-Commerce buyer identity digest",
        ),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid ACP-Commerce digest: {field}")))?;
    }
    let passport_ref = required_json_str(
        value,
        "transaction_passport_ref",
        "missing ACP-Commerce transaction passport ref",
    )?;
    if passport_ref != envelope.transaction_passport_ref {
        return Err(claim_failed("ACP-Commerce checkout passport mismatch"));
    }
    required_json_str(value, "order_id", "missing ACP-Commerce order id")?;
    let amount_units = required_json_u64(value, "amount_units", "missing ACP-Commerce amount")?;
    if amount_units == 0 {
        return Err(claim_failed("ACP-Commerce amount missing"));
    }
    let currency = required_json_str(value, "currency", "missing ACP-Commerce currency")?;
    if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(claim_failed("unsupported ACP-Commerce currency"));
    }
    let status = required_json_str(value, "status", "missing ACP-Commerce status")?;
    if !matches!(status, "authorized" | "captured" | "settled" | "refunded") {
        return Err(claim_failed("unsupported ACP-Commerce status"));
    }
    if status == "refunded" {
        return Err(claim_failed("ACP-Commerce payment was refunded"));
    }
    let checkout_receipt_ref = required_json_str(
        value,
        "chio_checkout_receipt_ref",
        "missing ACP-Commerce checkout receipt ref",
    )?;
    if !envelope
        .receipt_refs
        .iter()
        .any(|receipt_ref| receipt_ref == checkout_receipt_ref)
    {
        return Err(claim_failed(
            "ACP-Commerce checkout receipt ref is not bound",
        ));
    }
    Ok(())
}
