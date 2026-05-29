//! AWS Marketplace contract helpers for the Chio Bedrock listing.
//!
//! The crate models the fail-closed entitlement and metering contract used
//! by the AWS Marketplace SaaS listing. The public APIs are deterministic and
//! testable without AWS credentials. Production callers can bind these
//! decisions to `aws-sdk-marketplaceentitlement` and
//! `aws-sdk-marketplacemetering` clients at the process edge.

#![forbid(unsafe_code)]

pub mod entitlement;
pub mod metering;

use serde::{Deserialize, Serialize};

pub use entitlement::{EntitlementDecision, EntitlementError, EntitlementRecord, EntitlementStore};
pub use metering::{
    batch_meter_usage, meter_usage, MeteringApi, MeteringBatch, MeteringError, MeteringEvent,
    MeteringUsage,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MarketplaceSdkClientTypes {
    pub entitlement_client: &'static str,
    pub metering_client: &'static str,
}

pub fn marketplace_sdk_client_type_names() -> MarketplaceSdkClientTypes {
    MarketplaceSdkClientTypes {
        entitlement_client: std::any::type_name::<aws_sdk_marketplaceentitlement::Client>(),
        metering_client: std::any::type_name::<aws_sdk_marketplacemetering::Client>(),
    }
}
