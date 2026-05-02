use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::entitlement::{EntitlementError, EntitlementStore};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeteringUsage {
    pub customer_identifier: String,
    pub product_code: String,
    pub dimension: String,
    pub quantity: u32,
    pub timestamp_epoch_secs: u64,
    pub receipt_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeteringEvent {
    pub api: MeteringApi,
    pub customer_identifier: String,
    pub product_code: String,
    pub dimension: String,
    pub quantity: u32,
    pub timestamp_epoch_secs: u64,
    pub receipt_id: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MeteringApi {
    MeterUsage,
    BatchMeterUsage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeteringBatch {
    pub records: Vec<MeteringUsage>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MeteringError {
    #[error("metering quantity must be positive")]
    QuantityMustBePositive,
    #[error("receipt id is required")]
    MissingReceiptId,
    #[error("marketplace entitlement rejected metering: {0}")]
    Entitlement(#[from] EntitlementError),
}

pub fn meter_usage(
    entitlements: &EntitlementStore,
    usage: MeteringUsage,
    now_epoch_secs: u64,
) -> Result<MeteringEvent, MeteringError> {
    validate_usage(&usage)?;
    entitlements.check(
        &usage.customer_identifier,
        &usage.product_code,
        &usage.dimension,
        now_epoch_secs,
    )?;

    Ok(MeteringEvent {
        api: MeteringApi::MeterUsage,
        customer_identifier: usage.customer_identifier,
        product_code: usage.product_code,
        dimension: usage.dimension,
        quantity: usage.quantity,
        timestamp_epoch_secs: usage.timestamp_epoch_secs,
        receipt_id: usage.receipt_id,
    })
}

pub fn batch_meter_usage(
    entitlements: &EntitlementStore,
    batch: MeteringBatch,
    now_epoch_secs: u64,
) -> Result<Vec<MeteringEvent>, MeteringError> {
    let mut events = Vec::with_capacity(batch.records.len());
    for usage in batch.records {
        let mut event = meter_usage(entitlements, usage, now_epoch_secs)?;
        event.api = MeteringApi::BatchMeterUsage;
        events.push(event);
    }
    Ok(events)
}

fn validate_usage(usage: &MeteringUsage) -> Result<(), MeteringError> {
    if usage.quantity == 0 {
        return Err(MeteringError::QuantityMustBePositive);
    }
    if usage.receipt_id.trim().is_empty() {
        return Err(MeteringError::MissingReceiptId);
    }
    Ok(())
}
