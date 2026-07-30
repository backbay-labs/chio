//! `chio.finding.finalized-bond-snapshot.v1`: the settlement observer's
//! signed reading of one collateral allocation at one finalized block.
//!
//! Enforcement needs live collateral, not a promise. The bond-backing
//! allocation states what was reserved; this snapshot states what the chain
//! actually held, at which block, under which finality policy, and observed
//! by which operator key. Both are required: the allocation bounds the
//! promise and the snapshot bounds the money.
//!
//! The arithmetic is checked here rather than assumed downstream. Held and
//! slashed amounts are carved out of the locked amount, so their sum can
//! never exceed it, and all three share one currency.

use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use crate::envelope::require_ed25519;
use crate::validate::{
    require_bounded_id, require_chain_hash, require_currency, require_hex64, require_i_json_u64,
    require_nonzero, FindingError,
};

/// Settlement-observer-signed finalized bond snapshot.
pub const FINDING_FINALIZED_BOND_SNAPSHOT_SCHEMA_V1: &str =
    chio_core_types::signed_artifact::CHIO_FINDING_FINALIZED_BOND_SNAPSHOT_V1_SCHEMA;

/// The exact vault an allocation lives in. Every member is required: a
/// vault id without its chain and contract names nothing enforceable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingVaultReference {
    pub chain_id: String,
    pub vault_contract: String,
    pub vault_id: String,
}

impl FindingVaultReference {
    pub(crate) fn validate(&self) -> Result<(), FindingError> {
        require_bounded_id(&self.chain_id, "vault.chain_id")?;
        require_bounded_id(&self.vault_contract, "vault.vault_contract")?;
        require_bounded_id(&self.vault_id, "vault.vault_id")
    }
}

/// How final the observed block is. Closed vocabulary: a chain with
/// deterministic finality says so, and a probabilistic chain states the
/// confirmation depth it actually observed rather than asserting finality
/// it cannot prove.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FindingObservedFinality {
    Finalized,
    Confirmations { depth: u64 },
}

impl FindingObservedFinality {
    fn validate(&self) -> Result<(), FindingError> {
        match self {
            FindingObservedFinality::Finalized => Ok(()),
            FindingObservedFinality::Confirmations { depth } => {
                require_nonzero(*depth, "observed_finality.depth")
            }
        }
    }
}

/// Finalized bond snapshot body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingFinalizedBondSnapshot {
    pub schema: String,
    /// Content-addressed: sha256 of the canonical body with `snapshot_id`
    /// cleared.
    pub snapshot_id: String,
    pub chain_id: String,
    pub vault_contract: String,
    pub vault_id: String,
    pub seller: PublicKey,
    pub allocation_id: String,
    pub locked_amount: u64,
    pub held_amount: u64,
    pub slashed_amount: u64,
    /// One currency for all three amounts.
    pub currency: String,
    pub block_number: u64,
    pub block_hash: String,
    /// The finality policy this observation was taken under.
    pub finality_policy: String,
    pub observed_finality: FindingObservedFinality,
    /// Registry record for the observing operator's identity.
    pub identity_registry_record: String,
    pub operator_key_hash: String,
    pub operator_key_epoch: u64,
    pub observed_at: u64,
}

/// Settlement-observer-signed envelope for the snapshot.
pub type SignedFindingFinalizedBondSnapshot = SignedExportEnvelope<FindingFinalizedBondSnapshot>;

impl FindingFinalizedBondSnapshot {
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_FINALIZED_BOND_SNAPSHOT_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.snapshot_id, "snapshot_id")?;
        self.vault().validate()?;
        require_ed25519(&self.seller, "seller")?;
        require_hex64(&self.allocation_id, "allocation_id")?;
        require_nonzero(self.locked_amount, "locked_amount")?;
        require_i_json_u64(self.held_amount, "held_amount")?;
        require_i_json_u64(self.slashed_amount, "slashed_amount")?;
        let encumbered = self
            .held_amount
            .checked_add(self.slashed_amount)
            .ok_or(FindingError::AmountOverflow("finalized_bond_snapshot"))?;
        if encumbered > self.locked_amount {
            return Err(FindingError::InvalidField("held_amount"));
        }
        require_currency(&self.currency, "currency")?;
        require_nonzero(self.block_number, "block_number")?;
        require_chain_hash(&self.block_hash, "block_hash")?;
        require_bounded_id(&self.finality_policy, "finality_policy")?;
        self.observed_finality.validate()?;
        require_bounded_id(&self.identity_registry_record, "identity_registry_record")?;
        require_chain_hash(&self.operator_key_hash, "operator_key_hash")?;
        require_nonzero(self.operator_key_epoch, "operator_key_epoch")?;
        require_nonzero(self.observed_at, "observed_at")?;
        self.verify_snapshot_id()
    }

    /// The vault this snapshot observed, as the reference the enforcement
    /// artifact carries.
    #[must_use]
    pub fn vault(&self) -> FindingVaultReference {
        FindingVaultReference {
            chain_id: self.chain_id.clone(),
            vault_contract: self.vault_contract.clone(),
            vault_id: self.vault_id.clone(),
        }
    }

    /// Collateral still available to impair: locked minus what is already
    /// held or slashed, with checked arithmetic.
    pub fn live_allocated_collateral(&self) -> Result<u64, FindingError> {
        let encumbered = self
            .held_amount
            .checked_add(self.slashed_amount)
            .ok_or(FindingError::AmountOverflow("finalized_bond_snapshot"))?;
        self.locked_amount
            .checked_sub(encumbered)
            .ok_or(FindingError::AmountOverflow("finalized_bond_snapshot"))
    }

    /// Recompute and compare the content-addressed snapshot id.
    pub fn verify_snapshot_id(&self) -> Result<(), FindingError> {
        let expected = compute_snapshot_id(self)?;
        if expected == self.snapshot_id {
            Ok(())
        } else {
            Err(FindingError::ArtifactIdMismatch("snapshot_id"))
        }
    }
}

/// Content-addressed snapshot id: sha256 over the canonical body with
/// `snapshot_id` cleared.
pub fn compute_snapshot_id(
    snapshot: &FindingFinalizedBondSnapshot,
) -> Result<String, FindingError> {
    let mut body = snapshot.clone();
    body.snapshot_id = String::new();
    let bytes =
        chio_core_types::canonical_json_bytes(&body).map_err(|_| FindingError::Canonicalization)?;
    Ok(chio_core_types::crypto::sha256_hex(&bytes))
}

/// Verify a signed snapshot against the externally pinned settlement
/// observer. The body names the seller and the operator key hash, never the
/// signing authority, so the pin is the only thing that authorizes it.
pub fn verify_signed_finalized_bond_snapshot(
    signed: &SignedFindingFinalizedBondSnapshot,
    pinned_settlement_observer: &PublicKey,
) -> Result<(), FindingError> {
    signed.body.validate()?;
    crate::envelope::verify_pinned_envelope(
        signed,
        pinned_settlement_observer,
        "finalized_bond_snapshot",
    )
}
