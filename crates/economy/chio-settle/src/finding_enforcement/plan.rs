//! Preparation of the exact call one verified enforcement authorizes.

use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::PublicKey;
use chio_core::receipt::decision::Decision;
use chio_core::web3::anchors::{verify_anchor_inclusion_proof, AnchorInclusionProof};
use chio_finding::{
    signed_envelope_sha256, verify_signed_authority_status, FindingEffectIntentKind,
    SignedFindingAuthorityStatus, SignedFindingChallengeEnforcement,
    FINDING_AUTHORITY_STATUS_SCHEMA_V1,
};

use super::verify::{
    FindingPenaltyAuthorityPolicy, ReconciledFindingEnforcement, VerifiedFindingEnforcement,
};
use super::{parse_chain_hash, parse_evm_address, reject};
use crate::{
    prepare_bond_impair, scale_chio_amount_to_token_minor_units, EvmBondSnapshot,
    PreparedBondImpair, PreparedEvmCall, SettlementChainConfig, SettlementError,
};

/// Tool server recorded by the anchored receipt that authorizes one finding
/// enforcement root.
pub const FINDING_ENFORCEMENT_ANCHOR_TOOL_SERVER: &str = "chio-control-plane";

/// Tool name recorded by the anchored receipt that authorizes one finding
/// enforcement root.
pub const FINDING_ENFORCEMENT_ANCHOR_TOOL_NAME: &str = "finding.enforcement-root";

/// Schema of the exact enforcement identity committed by the anchored
/// receipt leaf.
pub const FINDING_ENFORCEMENT_ANCHOR_SCHEMA_V1: &str = "chio.finding.enforcement-anchor.v1";

/// Independently retained authority and lifecycle evidence for the kernel
/// that published an enforcement-root receipt.
///
/// The proof cannot select this policy or the status signer. Callers obtain
/// both from deployment governance and its authenticated revocation source.
#[derive(Debug, Clone, Copy)]
pub struct FindingAnchorPublisherEvidence<'a> {
    pub retained_policy: &'a FindingPenaltyAuthorityPolicy,
    pub signed_status: &'a SignedFindingAuthorityStatus,
    pub status_authority: &'a PublicKey,
    pub max_status_age_secs: u64,
    pub trusted_now_secs: u64,
}

/// Build the exact action parameters an enforcement-root receipt must carry.
///
/// Root publishers use this value when requesting the mediated receipt. The
/// planner compares the signed, Merkle-included action against the same value
/// before it returns a dispatchable impairment.
#[must_use]
pub fn finding_enforcement_anchor_parameters(
    verified: &VerifiedFindingEnforcement,
) -> serde_json::Value {
    enforcement_anchor_parameters(
        verified.root_intent_id(),
        verified.seller_impair_intent_id(),
        &verified.enforcement().enforcement_id,
        verified.enforcement_envelope_sha256(),
        &verified.enforcement().penalty_envelope_sha256,
        &verified.enforcement().liability_key,
    )
}

/// Build the mediated anchor action directly from a signed enforcement.
///
/// Root publication precedes impairment verification, so publishers use this
/// form to obtain the exact anchored receipt later consumed by the planner.
pub fn finding_enforcement_anchor_parameters_for_artifact(
    enforcement: &SignedFindingChallengeEnforcement,
) -> Result<serde_json::Value, SettlementError> {
    let root_intent_id = unique_effect_intent(enforcement, FindingEffectIntentKind::RootIntent)?;
    let seller_impair_intent_id =
        unique_effect_intent(enforcement, FindingEffectIntentKind::SellerImpair)?;
    let enforcement_envelope_sha256 = signed_envelope_sha256(enforcement)
        .map_err(|error| reject(format!("enforcement envelope digest rejected: {error}")))?;
    Ok(enforcement_anchor_parameters(
        root_intent_id,
        seller_impair_intent_id,
        &enforcement.body.enforcement_id,
        &enforcement_envelope_sha256,
        &enforcement.body.penalty_envelope_sha256,
        &enforcement.body.liability_key,
    ))
}

fn unique_effect_intent(
    enforcement: &SignedFindingChallengeEnforcement,
    kind: FindingEffectIntentKind,
) -> Result<&str, SettlementError> {
    let mut matches = enforcement
        .body
        .effect_intents
        .iter()
        .filter(|binding| binding.kind == kind);
    let intent = matches
        .next()
        .ok_or_else(|| reject(format!("enforcement lacks {kind:?} intent binding")))?;
    if matches.next().is_some() {
        return Err(reject(format!(
            "enforcement carries more than one {kind:?} intent binding"
        )));
    }
    Ok(&intent.intent_id)
}

fn enforcement_anchor_parameters(
    root_intent_id: &str,
    seller_impair_intent_id: &str,
    enforcement_id: &str,
    enforcement_envelope_sha256: &str,
    penalty_envelope_sha256: &str,
    liability_key: &str,
) -> serde_json::Value {
    serde_json::json!({
        "schema": FINDING_ENFORCEMENT_ANCHOR_SCHEMA_V1,
        "root_intent_id": root_intent_id,
        "seller_impair_intent_id": seller_impair_intent_id,
        "enforcement_id": enforcement_id,
        "enforcement_envelope_sha256": enforcement_envelope_sha256,
        "penalty_envelope_sha256": penalty_envelope_sha256,
        "liability_key": liability_key,
    })
}

fn require_enforcement_anchor_binding(
    verified: &VerifiedFindingEnforcement,
    anchor_proof: &AnchorInclusionProof,
    publisher: FindingAnchorPublisherEvidence<'_>,
) -> Result<(), SettlementError> {
    require_anchor_publisher_role_separation(verified, publisher.retained_policy)?;
    verify_anchor_inclusion_proof(anchor_proof)
        .map_err(|error| reject(format!("anchor proof rejected: {error}")))?;
    require_anchor_publisher_lifecycle(anchor_proof, publisher)?;
    let receipt = &anchor_proof.receipt;
    if receipt.tool_server != FINDING_ENFORCEMENT_ANCHOR_TOOL_SERVER
        || receipt.tool_name != FINDING_ENFORCEMENT_ANCHOR_TOOL_NAME
        || receipt.decision != Some(Decision::Allow)
    {
        return Err(reject(
            "anchor proof receipt does not authorize a finding enforcement root",
        ));
    }
    if !receipt
        .action
        .verify_hash()
        .map_err(|error| reject(format!("anchor proof action hash rejected: {error}")))?
    {
        return Err(reject(
            "anchor proof action hash does not match its parameters",
        ));
    }
    if receipt.action.parameters != finding_enforcement_anchor_parameters(verified) {
        return Err(reject(
            "anchor proof receipt does not bind this enforcement, penalty, and root intent",
        ));
    }
    Ok(())
}

pub(super) fn require_anchor_publisher_role_separation(
    verified: &VerifiedFindingEnforcement,
    policy: &FindingPenaltyAuthorityPolicy,
) -> Result<(), SettlementError> {
    let enforcement = verified.enforcement();
    if policy.key == enforcement.finalization_key || policy.key == enforcement.penalty_key {
        return Err(reject(
            "anchor publisher must be distinct from finalization and penalty authorities",
        ));
    }
    Ok(())
}

pub(super) fn require_anchor_publisher_lifecycle(
    proof: &AnchorInclusionProof,
    evidence: FindingAnchorPublisherEvidence<'_>,
) -> Result<(), SettlementError> {
    let policy = evidence.retained_policy;
    policy.validate("anchor publisher")?;
    if evidence.status_authority == &policy.key {
        return Err(reject(
            "anchor publisher and authority status signer must be distinct keys",
        ));
    }
    if evidence.max_status_age_secs == 0 {
        return Err(reject(
            "anchor publisher status maximum age must be nonzero",
        ));
    }

    let receipt_at = proof.receipt.timestamp;
    let published_at = proof.checkpoint_statement.issued_at;
    let certificate = &proof.key_binding_certificate.certificate;
    if proof.receipt.kernel_key != policy.key
        || proof.checkpoint_statement.kernel_key != policy.key
        || certificate.chio_public_key != policy.key
    {
        return Err(reject(
            "anchor proof publisher does not match the retained governance policy",
        ));
    }
    if published_at < policy.valid_from || published_at >= policy.valid_until {
        return Err(reject(
            "anchor proof was published outside the retained authority window",
        ));
    }
    if published_at < certificate.issued_at || published_at >= certificate.expires_at {
        return Err(reject(
            "anchor proof was published outside its key-binding certificate window",
        ));
    }
    if receipt_at < policy.valid_from || receipt_at >= policy.valid_until {
        return Err(reject(
            "anchor receipt was signed outside the retained authority window",
        ));
    }
    if receipt_at < certificate.issued_at || receipt_at >= certificate.expires_at {
        return Err(reject(
            "anchor receipt was signed outside its key-binding certificate window",
        ));
    }
    if receipt_at > published_at {
        return Err(reject(
            "anchor receipt was signed after its enclosing checkpoint",
        ));
    }

    verify_signed_authority_status(evidence.signed_status, evidence.status_authority)
        .map_err(|error| reject(format!("anchor publisher status rejected: {error}")))?;
    let status = &evidence.signed_status.body;
    if status.schema != FINDING_AUTHORITY_STATUS_SCHEMA_V1
        || status.status_ref != policy.revocation_status_ref
        || status.authority_id != policy.authority_id
        || status.key != policy.key
        || status.key_epoch != policy.key_epoch
    {
        return Err(reject(
            "anchor publisher status does not bind the retained governance policy",
        ));
    }
    if status.observed_at < published_at || status.observed_at > evidence.trusted_now_secs {
        return Err(reject(
            "anchor publisher status is not a post-publication trusted-time reading",
        ));
    }
    if evidence.trusted_now_secs.saturating_sub(status.observed_at) > evidence.max_status_age_secs {
        return Err(reject(
            "anchor publisher status is older than the configured maximum age",
        ));
    }
    if status
        .revoked_from
        .is_some_and(|revoked_from| revoked_from > status.observed_at)
    {
        return Err(reject(
            "anchor publisher status declares an unobserved future revocation",
        ));
    }
    if status
        .revoked_from
        .is_some_and(|revoked_from| revoked_from <= published_at)
    {
        return Err(reject(
            "anchor publisher was revoked when the enforcement root was published",
        ));
    }
    Ok(())
}

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

/// A frozen impairment reconstructed solely for post-dispatch observation.
///
/// Its prepared call remains private to this module, so the public dispatch
/// function cannot accept reconciliation-only authority.
#[derive(Debug, Clone)]
pub struct PlannedFindingImpairmentReconciliation {
    planned: PlannedFindingImpairment,
}

impl PlannedFindingImpairmentReconciliation {
    /// The frozen semantic intent recovered from the authenticated artifacts.
    #[must_use]
    pub const fn intent(&self) -> &FindingImpairmentIntent {
        self.planned.intent()
    }

    pub(super) const fn planned(&self) -> &PlannedFindingImpairment {
        &self.planned
    }
}

/// Compose the shipped bond-impair preparation for a verified enforcement.
///
/// `vault_snapshot` is the live contract read; the signed snapshot inside
/// `verified` is the observer's attestation. Both are required and both must
/// name the same vault and operator key: the attestation bounds the money and
/// the contract read bounds the call.
///
/// The ordered destinations are already part of the verified enforcement.
/// Constructing that capability checked every address against the operator
/// policy supplied independently of the signed instruction, so the planner
/// can preserve the exact authorized ordering without accepting new input.
pub fn plan_finding_impairment(
    config: &SettlementChainConfig,
    verified: &VerifiedFindingEnforcement,
    operator_address: &str,
    vault_snapshot: &EvmBondSnapshot,
    anchor_proof: &AnchorInclusionProof,
    anchor_publisher: FindingAnchorPublisherEvidence<'_>,
) -> Result<PlannedFindingImpairment, SettlementError> {
    config.validate()?;
    let enforcement = verified.enforcement();
    let snapshot = verified.snapshot();
    require_enforcement_anchor_binding(verified, anchor_proof, anchor_publisher)?;

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

    let mut beneficiaries = Vec::with_capacity(enforcement.destinations.len());
    let mut shares = Vec::with_capacity(enforcement.destinations.len());
    let mut destinations = Vec::with_capacity(enforcement.destinations.len());
    for destination in &enforcement.destinations {
        parse_evm_address(
            &destination.destination,
            "finding impairment enforcement destination",
        )?;
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

/// Reconstruct the exact frozen call for observation without granting
/// dispatch authority.
pub fn plan_finding_impairment_for_reconciliation(
    config: &SettlementChainConfig,
    verified: &ReconciledFindingEnforcement,
    operator_address: &str,
    vault_snapshot: &EvmBondSnapshot,
    anchor_proof: &AnchorInclusionProof,
    anchor_publisher: FindingAnchorPublisherEvidence<'_>,
) -> Result<PlannedFindingImpairmentReconciliation, SettlementError> {
    plan_finding_impairment(
        config,
        verified.verified(),
        operator_address,
        vault_snapshot,
        anchor_proof,
        anchor_publisher,
    )
    .map(|planned| PlannedFindingImpairmentReconciliation { planned })
}
