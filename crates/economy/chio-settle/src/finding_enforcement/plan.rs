//! Preparation of the exact call one verified enforcement authorizes.

use chio_core::capability::scope::MonetaryAmount;
use chio_core::web3::anchors::AnchorInclusionProof;

use super::verify::VerifiedFindingEnforcement;
use super::{parse_chain_hash, parse_evm_address, reject};
use crate::{
    prepare_bond_impair, scale_chio_amount_to_token_minor_units, EvmBondSnapshot,
    PreparedBondImpair, PreparedEvmCall, SettlementChainConfig, SettlementError,
};

/// One frozen payout leg: the enforcement's ordered destination and the
/// token-denominated share the prepared call carries for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingImpairmentDestination {
    /// Immutable rail-tagged destination taken from the enforcement.
    pub destination: String,
    /// Share in the enforcement currency.
    pub amount: MonetaryAmount,
    /// The same share in settlement-token minor units.
    pub share_minor_units: u128,
}

/// The frozen semantic intent for one seller impairment.
///
/// Everything a later reconciliation needs to prove a transaction is *this*
/// impairment is fixed here before anything is broadcast: the evidence hash,
/// the target contract and vault, the amount, and the ordered destinations.
/// Publisher-chosen state (attempt keys, nonces, gas) is deliberately absent,
/// so a retry that picks a different nonce still reconciles against the same
/// intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingImpairmentIntent {
    /// Domain-keyed identity of the seller-impairment effect.
    pub intent_id: String,
    /// Enforcement instruction that authorized it.
    pub enforcement_id: String,
    /// Liability this impairment settles. A second corroborating challenge
    /// maps to the same key and cannot authorize a second slash.
    pub liability_key: String,
    /// Exact signed bond snapshot the amount was checked against.
    pub bond_snapshot_envelope_sha256: String,
    /// Chain the call must execute on.
    pub chain_id: String,
    /// Bond vault the call must target.
    pub target_contract: String,
    /// Vault the call must impair.
    pub vault_id: String,
    /// `evidenceHash` the vault consumes exactly once.
    pub evidence_hash: String,
    /// Proof root the vault verifies the action against.
    pub merkle_root: String,
    /// Total slashed, in the enforcement currency.
    pub amount: MonetaryAmount,
    /// The same total in settlement-token minor units.
    pub slash_amount_minor_units: u128,
    /// Ordered destinations whose shares sum exactly to the total.
    pub destinations: Vec<FindingImpairmentDestination>,
}

/// A frozen intent paired with the prepared call that satisfies it.
///
/// This is preparation, not publication. [`PreparedBondImpair`] deliberately
/// does not implement `PreparedEvmSubmission`, and the impair selector sits in
/// the guarded money-exit set, so the generic submit path refuses it: the call
/// can only leave through a durable publisher.
#[derive(Debug, Clone)]
pub struct PlannedFindingImpairment {
    intent: FindingImpairmentIntent,
    prepared: PreparedBondImpair,
}

impl PlannedFindingImpairment {
    /// The frozen semantic intent to persist and fence before dispatch.
    #[must_use]
    pub const fn intent(&self) -> &FindingImpairmentIntent {
        &self.intent
    }

    /// The prepared vault call.
    #[must_use]
    pub const fn prepared(&self) -> &PreparedBondImpair {
        &self.prepared
    }

    /// The raw call a publisher would broadcast.
    #[must_use]
    pub const fn call(&self) -> &PreparedEvmCall {
        self.prepared.call()
    }
}

/// Compose the shipped bond-impair preparation for a verified enforcement.
///
/// `vault_snapshot` is the live contract read; the signed snapshot inside
/// `verified` is the observer's attestation. Both are required and both must
/// name the same vault and operator key: the attestation bounds the money and
/// the contract read bounds the call.
pub fn plan_finding_impairment(
    config: &SettlementChainConfig,
    verified: &VerifiedFindingEnforcement,
    operator_address: &str,
    vault_snapshot: &EvmBondSnapshot,
    anchor_proof: &AnchorInclusionProof,
) -> Result<PlannedFindingImpairment, SettlementError> {
    config.validate()?;
    let enforcement = verified.enforcement();
    let snapshot = verified.snapshot();

    if config.chain_id != snapshot.chain_id {
        return Err(reject(
            "settlement config chain_id does not match the bond snapshot chain_id",
        ));
    }
    if parse_evm_address(&config.bond_vault_contract, "config.bond_vault_contract")?
        != parse_evm_address(&snapshot.vault_contract, "bond snapshot vault_contract")?
    {
        return Err(reject(
            "settlement config bond_vault_contract does not match the bond snapshot vault_contract",
        ));
    }
    if parse_chain_hash(&vault_snapshot.vault_id, "vault_snapshot.vault_id")?
        != parse_chain_hash(&snapshot.vault_id, "bond snapshot vault_id")?
    {
        return Err(reject(
            "vault snapshot vault_id does not match the bond snapshot vault_id",
        ));
    }
    if parse_chain_hash(
        &vault_snapshot.operator_key_hash,
        "vault_snapshot.operator_key_hash",
    )? != parse_chain_hash(
        &snapshot.operator_key_hash,
        "bond snapshot operator_key_hash",
    )? {
        return Err(reject(
            "vault snapshot operator_key_hash does not match the bond snapshot operator_key_hash",
        ));
    }

    let allowed_destinations = config
        .policy
        .finding_impairment_destination_allowlist
        .iter()
        .map(|destination| {
            parse_evm_address(
                destination,
                "finding impairment destination allowlist entry",
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut beneficiaries = Vec::with_capacity(enforcement.destinations.len());
    let mut shares = Vec::with_capacity(enforcement.destinations.len());
    let mut destinations = Vec::with_capacity(enforcement.destinations.len());
    for destination in &enforcement.destinations {
        let parsed = parse_evm_address(
            &destination.destination,
            "finding impairment enforcement destination",
        )?;
        if !allowed_destinations.contains(&parsed) {
            return Err(reject(format!(
                "finding impairment destination {} is not in the operator allowlist",
                destination.destination
            )));
        }
        beneficiaries.push(destination.destination.clone());
        shares.push(destination.amount.clone());
        destinations.push(FindingImpairmentDestination {
            destination: destination.destination.clone(),
            amount: destination.amount.clone(),
            share_minor_units: scale_chio_amount_to_token_minor_units(&destination.amount, config)?,
        });
    }

    let prepared = prepare_bond_impair(
        config,
        operator_address,
        vault_snapshot,
        &enforcement.amount,
        &beneficiaries,
        &shares,
        anchor_proof,
    )?;

    let intent = FindingImpairmentIntent {
        intent_id: verified.seller_impair_intent_id().to_string(),
        enforcement_id: enforcement.enforcement_id.clone(),
        liability_key: enforcement.liability_key.clone(),
        bond_snapshot_envelope_sha256: verified.bond_snapshot_envelope_sha256().to_string(),
        chain_id: prepared.chain_id.clone(),
        target_contract: prepared.call().to_address.clone(),
        vault_id: prepared.vault_id.clone(),
        evidence_hash: prepared.evidence_hash.clone(),
        merkle_root: prepared.merkle_root.clone(),
        amount: enforcement.amount.clone(),
        slash_amount_minor_units: prepared.slash_amount_minor_units,
        destinations,
    };

    Ok(PlannedFindingImpairment { intent, prepared })
}
