//! Verify native operation evidence without the original gateway or database.
use anyhow::{Context, Result};
use chio_core::receipt::{body::ChioReceipt, decision::Decision};
use serde_json::Value;

pub fn verify_native(record: &Value, trusted: &str) -> Result<ChioReceipt> {
    let receipt: ChioReceipt = serde_json::from_value(record["receipt"].clone())
        .context("Native operation has no retained signed receipt")?;
    anyhow::ensure!(
        receipt.kernel_key.to_hex() == trusted && receipt.verify_signature()?,
        "Native receipt signer or signature does not match"
    );
    let context = receipt
        .metadata
        .as_ref()
        .context("Native receipt has no request context")?;
    anyhow::ensure!(
        receipt.tool_server == "fs"
            && receipt.tool_name == record["tool"]
            && receipt.action.parameter_hash == crate::digest(&record["arguments"])?
            && context["receipt_context"]["request_id"] == record["request_id"],
        "Native receipt does not bind these request arguments"
    );
    match record["state"].as_str() {
        Some("completed") => {
            anyhow::ensure!(receipt.decision == Some(Decision::Allow) && receipt.content_hash == crate::digest(&record["result"])? && context["admission_operation"]["projected_state"] == "completed", "Native result differs from its recorded completion");
        }
        Some("denied") => anyhow::ensure!(matches!(receipt.decision, Some(Decision::Deny { .. })), "Native refusal differs from its recorded verdict"),
        _ => anyhow::bail!("Native operation remains unresolved; inspect its retained decision and resource before continuing"),
    }
    Ok(receipt)
}
