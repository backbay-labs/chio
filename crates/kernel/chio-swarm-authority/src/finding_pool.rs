//! Authenticated pool allocation companion for cognition-market purchases.
//!
//! [`SwarmBudgetPool`] remains an unsigned planning object. A signed finding
//! pool allocation authenticates one exact canonical pool digest, one
//! purchaser, one currency, and one hard amount. It carries no debit state;
//! the kernel-owned ledger integration performs the qualifying atomic debit.

use chio_core_types::crypto::{
    canonical_json_bytes, sha256_hex, Keypair, PublicKey, SigningAlgorithm,
};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use crate::{SwarmAuthorityError, SwarmBudgetPool, CHIO_SWARM_BUDGET_POOL_SCHEMA};

pub const FINDING_POOL_ALLOCATION_SCHEMA_V1: &str =
    chio_core_types::CHIO_FINDING_POOL_ALLOCATION_V1_SCHEMA;
pub const FINDING_POOL_PURPOSE_V1: &str = "cognition_market_finding_purchase_v1";

/// Authority-signed companion for one unsigned swarm budget pool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingPoolAllocation {
    pub schema: String,
    /// SHA-256 of the canonical body with this field cleared.
    pub allocation_id: String,
    pub pool_id: String,
    pub pool_sha256: String,
    pub graph_id: String,
    pub purpose: String,
    pub purchaser_id: String,
    pub purchaser_key: PublicKey,
    pub currency: String,
    pub amount_units: u64,
    pub nonce: String,
    pub authority: PublicKey,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

pub type SignedFindingPoolAllocation = SignedExportEnvelope<FindingPoolAllocation>;

/// Verified allocation values passed across the kernel ledger boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFindingPoolAllocation {
    pub allocation_id: String,
    pub envelope_sha256: String,
    pub pool_id: String,
    pub pool_sha256: String,
    pub purchaser_id: String,
    pub purchaser_key: PublicKey,
    pub currency: String,
    pub amount_units: u64,
    pub expires_at_unix_ms: u64,
}

/// Canonical SHA-256 of the unsigned pool planning object.
pub fn swarm_budget_pool_sha256(pool: &SwarmBudgetPool) -> Result<String, SwarmAuthorityError> {
    let bytes = canonical_json_bytes(pool)
        .map_err(|error| SwarmAuthorityError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Canonical SHA-256 of the complete signed allocation envelope.
pub fn finding_pool_allocation_envelope_sha256(
    allocation: &SignedFindingPoolAllocation,
) -> Result<String, SwarmAuthorityError> {
    let bytes = canonical_json_bytes(allocation)
        .map_err(|error| SwarmAuthorityError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Compute the content-addressed allocation id.
pub fn compute_finding_pool_allocation_id(
    allocation: &FindingPoolAllocation,
) -> Result<String, SwarmAuthorityError> {
    let mut preimage = allocation.clone();
    preimage.allocation_id.clear();
    let bytes = canonical_json_bytes(&preimage)
        .map_err(|error| SwarmAuthorityError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Fill the content-addressed id and sign the allocation body.
pub fn sign_finding_pool_allocation(
    mut allocation: FindingPoolAllocation,
    keypair: &Keypair,
) -> Result<SignedFindingPoolAllocation, SwarmAuthorityError> {
    if allocation.authority != keypair.public_key() {
        return Err(rejected(
            "finding pool allocation authority does not match signing key",
        ));
    }
    allocation.allocation_id = compute_finding_pool_allocation_id(&allocation)?;
    SignedExportEnvelope::sign(allocation, keypair)
        .map_err(|error| SwarmAuthorityError::Canonical(error.to_string()))
}

/// Verify the signed companion against externally pinned authority and pool.
pub fn verify_finding_pool_allocation(
    signed: &SignedFindingPoolAllocation,
    pool: &SwarmBudgetPool,
    pinned_authority: &PublicKey,
    now_unix_ms: u64,
) -> Result<VerifiedFindingPoolAllocation, SwarmAuthorityError> {
    let body = &signed.body;
    if body.schema != FINDING_POOL_ALLOCATION_SCHEMA_V1 {
        return Err(rejected("unsupported finding pool allocation schema"));
    }
    if signed.signer_key != *pinned_authority
        || body.authority != *pinned_authority
        || signed.signer_key != body.authority
    {
        return Err(rejected("finding pool allocation authority mismatch"));
    }
    match signed.verify_signature() {
        Ok(true) => {}
        Ok(false) => return Err(rejected("finding pool allocation signature is invalid")),
        Err(error) => {
            return Err(SwarmAuthorityError::Canonical(error.to_string()));
        }
    }
    require_non_empty(&body.pool_id, "pool_id")?;
    require_non_empty(&body.graph_id, "graph_id")?;
    require_non_empty(&body.purchaser_id, "purchaser_id")?;
    require_non_empty(&body.nonce, "nonce")?;
    if body.purchaser_key.algorithm() != SigningAlgorithm::Ed25519 {
        return Err(rejected(
            "finding pool allocation purchaser key must be Ed25519",
        ));
    }
    if body.purpose != FINDING_POOL_PURPOSE_V1 {
        return Err(rejected("finding pool allocation purpose is invalid"));
    }
    require_currency(&body.currency)?;
    require_sha256(&body.allocation_id, "allocation_id")?;
    require_sha256(&body.pool_sha256, "pool_sha256")?;
    if body.amount_units == 0 {
        return Err(rejected("finding pool allocation amount must be positive"));
    }
    if body.issued_at_unix_ms >= body.expires_at_unix_ms {
        return Err(rejected(
            "finding pool allocation validity window is invalid",
        ));
    }
    if now_unix_ms < body.issued_at_unix_ms || now_unix_ms >= body.expires_at_unix_ms {
        return Err(rejected("finding pool allocation is not live"));
    }
    let expected_id = compute_finding_pool_allocation_id(body)?;
    if body.allocation_id != expected_id {
        return Err(rejected("finding pool allocation id mismatch"));
    }
    if pool.schema != CHIO_SWARM_BUDGET_POOL_SCHEMA
        || pool.pool_id != body.pool_id
        || pool.graph_id != body.graph_id
        || pool.currency != body.currency
    {
        return Err(rejected("finding pool allocation does not match the pool"));
    }
    if body.amount_units > pool.total_units {
        return Err(rejected(
            "finding pool allocation amount exceeds the unsigned pool total",
        ));
    }
    let pool_sha256 = swarm_budget_pool_sha256(pool)?;
    if body.pool_sha256 != pool_sha256 {
        return Err(rejected("finding pool allocation pool digest mismatch"));
    }
    Ok(VerifiedFindingPoolAllocation {
        allocation_id: body.allocation_id.clone(),
        envelope_sha256: finding_pool_allocation_envelope_sha256(signed)?,
        pool_id: body.pool_id.clone(),
        pool_sha256,
        purchaser_id: body.purchaser_id.clone(),
        purchaser_key: body.purchaser_key.clone(),
        currency: body.currency.clone(),
        amount_units: body.amount_units,
        expires_at_unix_ms: body.expires_at_unix_ms,
    })
}

fn require_non_empty(value: &str, field: &str) -> Result<(), SwarmAuthorityError> {
    if value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        Err(rejected(format!(
            "finding pool allocation {field} is invalid"
        )))
    } else {
        Ok(())
    }
}

fn require_currency(value: &str) -> Result<(), SwarmAuthorityError> {
    if !value.is_empty()
        && value.len() <= 16
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        Ok(())
    } else {
        Err(rejected("finding pool allocation currency is invalid"))
    }
}

fn require_sha256(value: &str, field: &str) -> Result<(), SwarmAuthorityError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(rejected(format!(
            "finding pool allocation {field} is not lowercase 64-hex"
        )))
    }
}

fn rejected(message: impl Into<String>) -> SwarmAuthorityError {
    SwarmAuthorityError::Rejected(message.into())
}

#[cfg(test)]
mod tests {
    use super::require_non_empty;

    #[test]
    fn allocation_identifiers_reject_whitespace_only_values() {
        assert!(require_non_empty("   ", "pool_id").is_err());
        assert!(require_non_empty("pool:one", "pool_id").is_ok());
    }
}
