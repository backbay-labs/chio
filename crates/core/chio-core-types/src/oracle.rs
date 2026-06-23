use alloc::string::String;

use serde::{Deserialize, Serialize};

use crate::crypto::{PublicKey, Signature};

pub const CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA: &str = "chio.oracle-conversion-evidence.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleConversionEvidence {
    pub schema: String,
    pub base: String,
    pub quote: String,
    pub authority: String,
    pub rate_numerator: u64,
    pub rate_denominator: u64,
    pub source: String,
    pub feed_address: String,
    pub updated_at: u64,
    pub max_age_seconds: u64,
    pub cache_age_seconds: u64,
    pub converted_cost_units: u64,
    pub original_cost_units: u64,
    pub original_currency: String,
    pub grant_currency: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle_public_key: Option<PublicKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}
