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
/// Versioned RFC 8785 preimage used by [`swarm_budget_pool_sha256`].
pub const SWARM_BUDGET_POOL_DIGEST_PROJECTION_SCHEMA_V1: &str =
    "chio.swarm.budget-pool-digest-projection.v1";

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
    /// Canonical decimal `u64` string. This remains lossless for RFC 8785
    /// implementations whose JSON number model is IEEE-754 binary64.
    pub amount_units: String,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SwarmBudgetPoolDigestProjection<'a> {
    schema: &'static str,
    pool_schema: &'a str,
    pool_id: &'a str,
    graph_id: &'a str,
    currency: &'a str,
    total_units: String,
    allocations: Vec<SwarmBudgetAllocationDigestProjection<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SwarmBudgetAllocationDigestProjection<'a> {
    allocation_id: &'a str,
    task_id: &'a str,
    dimension_id: &'a str,
    state: &'a crate::SwarmBudgetAllocationState,
    max_units: String,
    reserved_units: String,
    active_units: String,
    consumed_units: String,
    released_units: String,
    reversed_units: String,
}

/// RFC 8785 bytes of the versioned budget-pool digest projection.
///
/// This is deliberately not the JSON serialization of
/// `chio.swarm.budget-pool.v1`. Every `u64` is projected to its shortest
/// unsigned base-10 string, and allocation order is preserved. The schema
/// field versions this exact preimage independently from the planning object.
pub fn swarm_budget_pool_digest_projection_bytes(
    pool: &SwarmBudgetPool,
) -> Result<Vec<u8>, SwarmAuthorityError> {
    let projection = SwarmBudgetPoolDigestProjection {
        schema: SWARM_BUDGET_POOL_DIGEST_PROJECTION_SCHEMA_V1,
        pool_schema: &pool.schema,
        pool_id: &pool.pool_id,
        graph_id: &pool.graph_id,
        currency: &pool.currency,
        total_units: pool.total_units.to_string(),
        allocations: pool
            .allocations
            .iter()
            .map(|allocation| SwarmBudgetAllocationDigestProjection {
                allocation_id: &allocation.allocation_id,
                task_id: &allocation.task_id,
                dimension_id: &allocation.dimension_id,
                state: &allocation.state,
                max_units: allocation.max_units.to_string(),
                reserved_units: allocation.reserved_units.to_string(),
                active_units: allocation.active_units.to_string(),
                consumed_units: allocation.consumed_units.to_string(),
                released_units: allocation.released_units.to_string(),
                reversed_units: allocation.reversed_units.to_string(),
            })
            .collect(),
    };
    canonical_json_bytes(&projection)
        .map_err(|error| SwarmAuthorityError::Canonical(error.to_string()))
}

/// SHA-256 of [`swarm_budget_pool_digest_projection_bytes`].
pub fn swarm_budget_pool_sha256(pool: &SwarmBudgetPool) -> Result<String, SwarmAuthorityError> {
    Ok(sha256_hex(&swarm_budget_pool_digest_projection_bytes(
        pool,
    )?))
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
    if pinned_authority.algorithm() != SigningAlgorithm::Ed25519 {
        return Err(rejected(
            "finding pool allocation authority must be Ed25519",
        ));
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
    let amount_units = parse_positive_u64_decimal(&body.amount_units)?;
    const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;
    if body.issued_at_unix_ms > I_JSON_MAX_SAFE_INTEGER
        || body.expires_at_unix_ms > I_JSON_MAX_SAFE_INTEGER
    {
        return Err(rejected(
            "finding pool allocation timestamps must be I-JSON safe integers",
        ));
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
    if amount_units > pool.total_units {
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
        amount_units,
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

fn parse_positive_u64_decimal(value: &str) -> Result<u64, SwarmAuthorityError> {
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(rejected(
            "finding pool allocation amount must be a canonical positive decimal u64",
        ));
    }
    value.parse::<u64>().map_err(|_| {
        rejected("finding pool allocation amount must be a canonical positive decimal u64")
    })
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
    use super::*;
    use chio_test_support::prelude::*;

    #[test]
    fn allocation_identifiers_reject_whitespace_only_values() {
        assert!(require_non_empty("   ", "pool_id").is_err());
        assert!(require_non_empty("pool:\u{0}one", "pool_id").is_err());
        assert!(require_non_empty("pool:one", "pool_id").is_ok());
    }

    #[test]
    fn allocation_amount_covers_the_full_u64_domain_without_json_rounding() {
        let authority = Keypair::from_seed(&[71; 32]);
        let purchaser = Keypair::from_seed(&[72; 32]);
        let pool = SwarmBudgetPool {
            schema: CHIO_SWARM_BUDGET_POOL_SCHEMA.to_string(),
            pool_id: "pool:max".to_string(),
            graph_id: "graph:max".to_string(),
            currency: "USD".to_string(),
            total_units: u64::MAX,
            allocations: vec![crate::SwarmBudgetAllocation {
                allocation_id: "allocation:max".to_owned(),
                task_id: "task:max".to_owned(),
                dimension_id: "dimension:max".to_owned(),
                state: crate::SwarmBudgetAllocationState::Consumed,
                max_units: u64::MAX,
                reserved_units: u64::MAX,
                active_units: u64::MAX,
                consumed_units: u64::MAX,
                released_units: u64::MAX,
                reversed_units: u64::MAX,
            }],
        };
        let expected_pool_projection = serde_json::json!({
            "schema": SWARM_BUDGET_POOL_DIGEST_PROJECTION_SCHEMA_V1,
            "poolSchema": CHIO_SWARM_BUDGET_POOL_SCHEMA,
            "poolId": "pool:max",
            "graphId": "graph:max",
            "currency": "USD",
            "totalUnits": u64::MAX.to_string(),
            "allocations": [{
                "allocationId": "allocation:max",
                "taskId": "task:max",
                "dimensionId": "dimension:max",
                "state": "consumed",
                "maxUnits": u64::MAX.to_string(),
                "reservedUnits": u64::MAX.to_string(),
                "activeUnits": u64::MAX.to_string(),
                "consumedUnits": u64::MAX.to_string(),
                "releasedUnits": u64::MAX.to_string(),
                "reversedUnits": u64::MAX.to_string()
            }]
        });
        let expected_pool_digest = sha256_hex(
            &canonical_json_bytes(&expected_pool_projection).test_expect("project pool amounts"),
        );
        assert_eq!(
            swarm_budget_pool_digest_projection_bytes(&pool).test_expect("project pool amounts"),
            canonical_json_bytes(&expected_pool_projection).test_expect("canonical projection")
        );
        assert_eq!(
            swarm_budget_pool_sha256(&pool).test_expect("hash projected pool"),
            expected_pool_digest
        );
        let signed = sign_finding_pool_allocation(
            FindingPoolAllocation {
                schema: FINDING_POOL_ALLOCATION_SCHEMA_V1.to_string(),
                allocation_id: String::new(),
                pool_id: pool.pool_id.clone(),
                pool_sha256: swarm_budget_pool_sha256(&pool).test_expect("hash pool"),
                graph_id: pool.graph_id.clone(),
                purpose: FINDING_POOL_PURPOSE_V1.to_string(),
                purchaser_id: "buyer:max".to_string(),
                purchaser_key: purchaser.public_key(),
                currency: "USD".to_string(),
                amount_units: u64::MAX.to_string(),
                nonce: "nonce:max".to_string(),
                authority: authority.public_key(),
                issued_at_unix_ms: 1,
                expires_at_unix_ms: 2,
            },
            &authority,
        )
        .test_expect("sign allocation");
        let json = serde_json::to_value(&signed).test_expect("serialize allocation");
        assert_eq!(json["body"]["amount_units"], u64::MAX.to_string());
        let verified = verify_finding_pool_allocation(&signed, &pool, &authority.public_key(), 1)
            .test_expect("verify full-domain amount");
        assert_eq!(verified.amount_units, u64::MAX);
    }

    #[test]
    fn allocation_amount_parser_rejects_values_above_u64() {
        assert_eq!(
            parse_positive_u64_decimal("18446744073709551615").test_expect("u64 max remains valid"),
            u64::MAX
        );
        assert!(parse_positive_u64_decimal("18446744073709551616").is_err());
    }
}
