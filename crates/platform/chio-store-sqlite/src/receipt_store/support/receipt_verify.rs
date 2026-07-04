use super::*;

pub(crate) fn unix_timestamp_now_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn sqlite_i64(value: u64, field: &str) -> Result<i64, ReceiptStoreError> {
    i64::try_from(value).map_err(|_| {
        ReceiptStoreError::Conflict(format!(
            "{field} value {value} exceeds SQLite INTEGER range"
        ))
    })
}

pub(crate) fn sqlite_u64(value: i64, field: &str) -> Result<u64, ReceiptStoreError> {
    u64::try_from(value).map_err(|_| {
        ReceiptStoreError::Conflict(format!(
            "{field} value {value} is outside the supported u64 range"
        ))
    })
}

pub(crate) fn sqlite_positive_u64(value: i64, field: &str) -> Result<u64, ReceiptStoreError> {
    let value = sqlite_u64(value, field)?;
    if value == 0 {
        return Err(ReceiptStoreError::Conflict(format!(
            "{field} must be greater than zero"
        )));
    }
    Ok(value)
}

pub(crate) fn sqlite_bool(value: bool) -> i64 {
    if value {
        1
    } else {
        0
    }
}

pub(crate) fn ensure_chio_receipt_verified(receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
    ensure_chio_receipt_verified_with_context(receipt, "tool receipt", None)
}

pub(crate) fn ensure_child_receipt_verified(
    receipt: &ChildRequestReceipt,
) -> Result<(), ReceiptStoreError> {
    ensure_child_receipt_verified_with_context(receipt, "child receipt", None)
}

fn format_receipt_context(
    receipt_kind: &str,
    receipt_id: Option<&str>,
    seq: Option<u64>,
) -> String {
    let mut context = receipt_kind.to_string();
    if let Some(seq) = seq {
        context.push_str(&format!(" seq {seq}"));
    }
    if let Some(receipt_id) = receipt_id {
        context.push_str(&format!(" receipt {receipt_id}"));
    }
    context
}

pub(crate) fn ensure_chio_receipt_verified_with_context(
    receipt: &ChioReceipt,
    receipt_kind: &str,
    seq: Option<u64>,
) -> Result<(), ReceiptStoreError> {
    let context = format_receipt_context(receipt_kind, Some(receipt.id.as_str()), seq);
    // The standalone SQLite verifier has no policy handle. Keep the
    // compatibility floor explicit: accept classical and hybrid receipts, while policy-bearing callers enforce their configured
    // floor before persistence or export.
    let signature_valid = receipt
        .verify_signature_with_floor(ReceiptCryptoFloor::AllowHybrid)
        .map_err(|error| {
            ReceiptStoreError::Conflict(format!("{context} verification failed: {error}"))
        })?;
    if !signature_valid {
        return Err(ReceiptStoreError::Conflict(format!(
            "{context} has invalid signature",
        )));
    }

    let parameter_hash_valid = receipt.action.verify_hash().map_err(|error| {
        ReceiptStoreError::Conflict(format!("{context} verification failed: {error}"))
    })?;
    if !parameter_hash_valid {
        return Err(ReceiptStoreError::Conflict(format!(
            "{context} has mismatched action parameter hash",
        )));
    }

    Ok(())
}

pub(crate) fn ensure_child_receipt_verified_with_context(
    receipt: &ChildRequestReceipt,
    receipt_kind: &str,
    seq: Option<u64>,
) -> Result<(), ReceiptStoreError> {
    let context = format_receipt_context(receipt_kind, Some(receipt.id.as_str()), seq);
    // The standalone SQLite verifier has no policy handle. Keep the
    // compatibility floor explicit: accept classical and hybrid receipts, while policy-bearing callers enforce their configured
    // floor before persistence or export.
    let signature_valid = receipt
        .verify_signature_with_floor(ReceiptCryptoFloor::AllowHybrid)
        .map_err(|error| {
            ReceiptStoreError::Conflict(format!("{context} verification failed: {error}"))
        })?;
    if !signature_valid {
        return Err(ReceiptStoreError::Conflict(format!(
            "{context} has invalid signature",
        )));
    }

    Ok(())
}

pub(crate) fn decode_verified_chio_receipt(
    raw_json: &str,
    receipt_kind: &str,
    seq: Option<u64>,
) -> Result<ChioReceipt, ReceiptStoreError> {
    let value: serde_json::Value = serde_json::from_str(raw_json).map_err(|error| {
        ReceiptStoreError::Conflict(format!(
            "{} failed to decode: {error}",
            format_receipt_context(receipt_kind, None, seq)
        ))
    })?;
    let receipt_id = value
        .get("id")
        .and_then(|field| field.as_str())
        .map(str::to_string);
    let receipt: ChioReceipt = serde_json::from_value(value).map_err(|error| {
        ReceiptStoreError::Conflict(format!(
            "{} failed to decode: {error}",
            format_receipt_context(receipt_kind, receipt_id.as_deref(), seq)
        ))
    })?;
    ensure_chio_receipt_verified_with_context(&receipt, receipt_kind, seq)?;
    Ok(receipt)
}

pub(crate) fn decode_verified_child_receipt(
    raw_json: &str,
    receipt_kind: &str,
    seq: Option<u64>,
) -> Result<ChildRequestReceipt, ReceiptStoreError> {
    let value: serde_json::Value = serde_json::from_str(raw_json).map_err(|error| {
        ReceiptStoreError::Conflict(format!(
            "{} failed to decode: {error}",
            format_receipt_context(receipt_kind, None, seq)
        ))
    })?;
    let receipt_id = value
        .get("id")
        .and_then(|field| field.as_str())
        .map(str::to_string);
    let receipt: ChildRequestReceipt = serde_json::from_value(value).map_err(|error| {
        ReceiptStoreError::Conflict(format!(
            "{} failed to decode: {error}",
            format_receipt_context(receipt_kind, receipt_id.as_deref(), seq)
        ))
    })?;
    ensure_child_receipt_verified_with_context(&receipt, receipt_kind, seq)?;
    Ok(receipt)
}
