//! Finding-specific settlement choke point.
//!
//! Two signed artifacts carry the whole authorization for impairing one
//! seller allocation: the venue finalization authority's enforcement
//! instruction and the settlement observer's finalized bond snapshot. This
//! module verifies that pair against externally pinned role keys, freezes
//! the exact call the enforcement authorizes, and reconciles what the chain
//! reports back.
//!
//! Three properties hold everywhere in here:
//!
//! - **Preparation is not publication.** [`plan_finding_impairment`] composes
//!   the shipped [`prepare_bond_impair`](crate::prepare_bond_impair) and
//!   returns a frozen intent plus a prepared call. Nothing in this module
//!   opens a socket; broadcast belongs to an injected
//!   [`FindingImpairmentPublisher`].
//! - **Ambiguity quarantines.** A slash is irreversible in v1, so an external
//!   observation that cannot be proved to match the frozen intent parks the
//!   liability for operator reconciliation. It is never reported as a
//!   confirmed impairment.
//! - **Roles are disjoint and pinned.** Neither artifact names the key that
//!   may authorize it. The pins are operator configuration, so a forged
//!   artifact cannot widen its own authorization, and a key valid in one role
//!   is rejected in the other.

mod plan;
mod publish;
mod reconcile;
mod verify;

#[cfg(test)]
mod tests;

pub use plan::{
    plan_finding_impairment, FindingImpairmentDestination, FindingImpairmentIntent,
    PlannedFindingImpairment,
};
pub use publish::{
    dispatch_finding_impairment, reobserve_finding_impairment, FindingImpairmentPublishError,
    FindingImpairmentPublisher,
};
pub use reconcile::{
    reconcile_finding_impairment, FindingImpairmentAttempt, FindingImpairmentOutcome,
    FindingImpairmentQuarantine, FindingVaultRejection, StoredImpairmentTransaction,
};
pub use verify::{
    recheck_finding_bond_observation, verify_finding_collateral_snapshot,
    verify_finding_enforcement, verify_finding_enforcement_for_reconciliation,
    FindingBondObservationRecheck, FindingBondObservationSource, FindingBondObservationVerdict,
    FindingEnforcementPins, FindingFinalityRequirement, FindingOperatorQualification,
    VerifiedFindingEnforcement,
};

use alloy_primitives::{Address, FixedBytes, B256};
use std::str::FromStr;

use crate::SettlementError;

/// Reject with the verification disposition every artifact and binding
/// failure in this module shares. The paired hook classification treats
/// verification failures as permanent, which is the correct routing: none of
/// these rejections can succeed on replay of the same bytes.
fn reject(detail: impl Into<String>) -> SettlementError {
    SettlementError::Verification(detail.into())
}

/// Parse an EVM address carried by a signed artifact or a durable record.
fn parse_evm_address(value: &str, field: &str) -> Result<Address, SettlementError> {
    Address::from_str(value).map_err(|error| reject(format!("{field} is not an address: {error}")))
}

/// Parse a 32-byte chain hash with the `0x` prefix optional, matching the
/// shape the finding artifacts validate.
fn parse_chain_hash(value: &str, field: &str) -> Result<B256, SettlementError> {
    let hash = chio_core::hashing::Hash::from_hex(value)
        .map_err(|error| reject(format!("{field} is not a 32-byte hash: {error}")))?;
    Ok(FixedBytes::from(*hash.as_bytes()))
}

/// Decode `0x`-prefixed call data.
fn decode_call_data(value: &str, field: &str) -> Result<Vec<u8>, SettlementError> {
    hex::decode(value.trim_start_matches("0x"))
        .map_err(|error| reject(format!("{field} is not hex: {error}")))
}
