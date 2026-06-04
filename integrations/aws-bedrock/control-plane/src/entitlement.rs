use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntitlementRecord {
    pub customer_identifier: String,
    pub product_code: String,
    pub dimension: String,
    pub expires_at_epoch_secs: u64,
    pub active: bool,
}

impl EntitlementRecord {
    pub fn key(&self) -> EntitlementKey {
        EntitlementKey {
            customer_identifier: self.customer_identifier.clone(),
            product_code: self.product_code.clone(),
            dimension: self.dimension.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntitlementDecision {
    pub customer_identifier: String,
    pub product_code: String,
    pub dimension: String,
    pub valid_until_epoch_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct EntitlementKey {
    customer_identifier: String,
    product_code: String,
    dimension: String,
}

impl EntitlementKey {
    pub fn new(
        customer_identifier: impl Into<String>,
        product_code: impl Into<String>,
        dimension: impl Into<String>,
    ) -> Self {
        Self {
            customer_identifier: customer_identifier.into(),
            product_code: product_code.into(),
            dimension: dimension.into(),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EntitlementError {
    #[error("customer identifier is required")]
    MissingCustomerIdentifier,
    #[error("product code is required")]
    MissingProductCode,
    #[error("dimension is required")]
    MissingDimension,
    #[error("marketplace entitlement was not found")]
    MissingEntitlement,
    #[error("marketplace entitlement is inactive")]
    InactiveEntitlement,
    #[error("marketplace entitlement expired at {expired_at_epoch_secs}")]
    ExpiredEntitlement { expired_at_epoch_secs: u64 },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntitlementStore {
    records: BTreeMap<EntitlementKey, EntitlementRecord>,
}

impl EntitlementStore {
    pub fn insert(&mut self, record: EntitlementRecord) -> Result<(), EntitlementError> {
        validate_non_empty(
            &record.customer_identifier,
            EntitlementError::MissingCustomerIdentifier,
        )?;
        validate_non_empty(&record.product_code, EntitlementError::MissingProductCode)?;
        validate_non_empty(&record.dimension, EntitlementError::MissingDimension)?;
        self.records.insert(record.key(), record);
        Ok(())
    }

    pub fn check(
        &self,
        customer_identifier: &str,
        product_code: &str,
        dimension: &str,
        now_epoch_secs: u64,
    ) -> Result<EntitlementDecision, EntitlementError> {
        validate_non_empty(
            customer_identifier,
            EntitlementError::MissingCustomerIdentifier,
        )?;
        validate_non_empty(product_code, EntitlementError::MissingProductCode)?;
        validate_non_empty(dimension, EntitlementError::MissingDimension)?;

        let key = EntitlementKey::new(customer_identifier, product_code, dimension);
        let record = self
            .records
            .get(&key)
            .ok_or(EntitlementError::MissingEntitlement)?;
        if !record.active {
            return Err(EntitlementError::InactiveEntitlement);
        }
        if record.expires_at_epoch_secs <= now_epoch_secs {
            return Err(EntitlementError::ExpiredEntitlement {
                expired_at_epoch_secs: record.expires_at_epoch_secs,
            });
        }

        Ok(EntitlementDecision {
            customer_identifier: record.customer_identifier.clone(),
            product_code: record.product_code.clone(),
            dimension: record.dimension.clone(),
            valid_until_epoch_secs: record.expires_at_epoch_secs,
        })
    }
}

fn validate_non_empty(value: &str, error: EntitlementError) -> Result<(), EntitlementError> {
    if value.trim().is_empty() || value.trim() != value {
        return Err(error);
    }
    Ok(())
}
