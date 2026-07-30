//! Fail-closed verification of the finding enforcement pair.

use chio_core::crypto::{PublicKey, SigningAlgorithm};
use chio_finding::{
    signed_envelope_sha256, verify_signed_challenge_enforcement,
    verify_signed_finalized_bond_snapshot, FindingChallengeEnforcement, FindingEffectIntentKind,
    FindingFinalizedBondSnapshot, FindingObservedFinality, SignedFindingChallengeEnforcement,
    SignedFindingFinalizedBondSnapshot,
};

use super::reject;
use crate::SettlementError;

/// Finality policy naming deterministic chain finality.
const DETERMINISTIC_FINALITY_POLICY: &str = "finalized";

/// Prefix of the probabilistic finality policy, completed by the minimum
/// confirmation depth the observer must have seen.
const CONFIRMATION_FINALITY_PREFIX: &str = "confirmations>=";

/// Externally pinned inputs for the finding settlement choke point.
///
/// Nothing here is read out of either artifact. The signer roles, the seller,
/// and the freshness bound are operator configuration, so a forged artifact
/// cannot widen its own authorization, and a key trusted to sign snapshots
/// cannot sign the instruction that spends against them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingEnforcementPins {
    /// The only key that may sign an enforcement instruction.
    pub finalization_authority: PublicKey,
    /// The only key that may sign a finalized bond snapshot.
    pub settlement_observer: PublicKey,
    /// Seller whose allocation this liability may impair, taken from the
    /// liability head. The enforcement instruction names the allocation but
    /// not its owner, so the owner is pinned here and checked against the
    /// snapshot rather than inferred.
    pub seller: PublicKey,
    /// Oldest bond observation this choke point will spend against, in
    /// seconds. Collateral moves between blocks, so an observation older than
    /// this bound is treated as unknown state rather than as available money.
    pub max_snapshot_age_secs: u64,
}

impl FindingEnforcementPins {
    /// Validate the pinned configuration itself.
    ///
    /// Role disjointness is checked here rather than at each use: one key
    /// holding two roles would let a single compromise both observe the
    /// collateral and authorize spending it.
    pub fn validate(&self) -> Result<(), SettlementError> {
        require_signing_key(&self.finalization_authority, "finalization_authority")?;
        require_signing_key(&self.settlement_observer, "settlement_observer")?;
        require_signing_key(&self.seller, "seller")?;
        let roles = [
            (
                &self.finalization_authority,
                &self.settlement_observer,
                "finalization_authority and settlement_observer",
            ),
            (
                &self.finalization_authority,
                &self.seller,
                "finalization_authority and seller",
            ),
            (
                &self.settlement_observer,
                &self.seller,
                "settlement_observer and seller",
            ),
        ];
        for (left, right, label) in roles {
            if left == right {
                return Err(SettlementError::InvalidInput(format!(
                    "{label} must be distinct keys"
                )));
            }
        }
        if self.max_snapshot_age_secs == 0 {
            return Err(SettlementError::InvalidInput(
                "max_snapshot_age_secs must be nonzero".to_string(),
            ));
        }
        Ok(())
    }
}

fn require_signing_key(key: &PublicKey, field: &str) -> Result<(), SettlementError> {
    if key.algorithm() != SigningAlgorithm::Ed25519 || key.is_weak_ed25519() {
        return Err(SettlementError::InvalidInput(format!(
            "{field} must be a non-weak Ed25519 key"
        )));
    }
    Ok(())
}

/// An enforcement instruction and bond snapshot that verified together.
///
/// There is no public constructor: the only way to hold one is to have run
/// [`verify_finding_enforcement`], so downstream preparation cannot be handed
/// an unverified pair.
#[derive(Debug, Clone)]
pub struct VerifiedFindingEnforcement {
    enforcement: FindingChallengeEnforcement,
    snapshot: FindingFinalizedBondSnapshot,
    enforcement_envelope_sha256: String,
    bond_snapshot_envelope_sha256: String,
    live_allocated_collateral: u64,
    seller_impair_intent_id: String,
}

impl VerifiedFindingEnforcement {
    /// The verified enforcement instruction body.
    #[must_use]
    pub const fn enforcement(&self) -> &FindingChallengeEnforcement {
        &self.enforcement
    }

    /// The verified bond snapshot body.
    #[must_use]
    pub const fn snapshot(&self) -> &FindingFinalizedBondSnapshot {
        &self.snapshot
    }

    /// Canonical digest of the exact signed enforcement envelope.
    #[must_use]
    pub fn enforcement_envelope_sha256(&self) -> &str {
        &self.enforcement_envelope_sha256
    }

    /// Canonical digest of the exact signed bond snapshot envelope, equal to
    /// the binding the enforcement carries.
    #[must_use]
    pub fn bond_snapshot_envelope_sha256(&self) -> &str {
        &self.bond_snapshot_envelope_sha256
    }

    /// Collateral the snapshot proved was still impairable: locked minus what
    /// is already held or slashed.
    #[must_use]
    pub const fn live_allocated_collateral(&self) -> u64 {
        self.live_allocated_collateral
    }

    /// Domain-keyed identity of the seller-impairment effect.
    #[must_use]
    pub fn seller_impair_intent_id(&self) -> &str {
        &self.seller_impair_intent_id
    }
}

/// Verify one enforcement instruction against the bond snapshot it binds.
///
/// `trusted_now_secs` is supplied by the caller because this crate owns no
/// clock. It must come from the coordinator's trusted time source, not from
/// either artifact: a snapshot that dated itself would otherwise certify its
/// own freshness.
pub fn verify_finding_enforcement(
    signed_enforcement: &SignedFindingChallengeEnforcement,
    signed_snapshot: &SignedFindingFinalizedBondSnapshot,
    pins: &FindingEnforcementPins,
    trusted_now_secs: u64,
) -> Result<VerifiedFindingEnforcement, SettlementError> {
    pins.validate()?;

    verify_signed_challenge_enforcement(signed_enforcement, &pins.finalization_authority)
        .map_err(|error| reject(format!("challenge enforcement rejected: {error}")))?;
    verify_signed_finalized_bond_snapshot(signed_snapshot, &pins.settlement_observer)
        .map_err(|error| reject(format!("finalized bond snapshot rejected: {error}")))?;

    let enforcement = &signed_enforcement.body;
    let snapshot = &signed_snapshot.body;

    let bond_snapshot_envelope_sha256 = signed_envelope_sha256(signed_snapshot)
        .map_err(|error| reject(format!("bond snapshot envelope digest failed: {error}")))?;
    if bond_snapshot_envelope_sha256 != enforcement.bond_snapshot_envelope_sha256 {
        return Err(reject(
            "enforcement bond_snapshot_envelope_sha256 does not bind the presented snapshot",
        ));
    }
    let enforcement_envelope_sha256 = signed_envelope_sha256(signed_enforcement)
        .map_err(|error| reject(format!("enforcement envelope digest failed: {error}")))?;

    if snapshot.vault() != enforcement.vault {
        return Err(reject(
            "bond snapshot vault does not match the enforcement vault",
        ));
    }
    if snapshot.allocation_id != enforcement.seller_allocation_id {
        return Err(reject(
            "bond snapshot allocation_id does not match the enforcement seller_allocation_id",
        ));
    }
    if snapshot.seller != pins.seller {
        return Err(reject(
            "bond snapshot seller does not match the pinned seller",
        ));
    }

    ensure_observed_finality_satisfies_policy(snapshot)?;

    if enforcement.amount.currency != snapshot.currency {
        return Err(reject(
            "enforcement amount currency does not match the bond snapshot currency",
        ));
    }
    let live_allocated_collateral = snapshot.live_allocated_collateral().map_err(|error| {
        reject(format!(
            "bond snapshot collateral is not computable: {error}"
        ))
    })?;
    if enforcement.amount.units > live_allocated_collateral {
        return Err(reject(
            "enforcement amount exceeds the live allocated collateral",
        ));
    }
    ensure_destinations_sum_exactly(enforcement)?;
    ensure_snapshot_is_fresh(snapshot, pins.max_snapshot_age_secs, trusted_now_secs)?;

    let seller_impair_intent_id = enforcement
        .effect_intents
        .iter()
        .find(|intent| intent.kind == FindingEffectIntentKind::SellerImpair)
        .map(|intent| intent.intent_id.clone())
        .ok_or_else(|| reject("enforcement carries no seller-impairment effect intent"))?;

    Ok(VerifiedFindingEnforcement {
        enforcement: enforcement.clone(),
        snapshot: snapshot.clone(),
        enforcement_envelope_sha256,
        bond_snapshot_envelope_sha256,
        live_allocated_collateral,
        seller_impair_intent_id,
    })
}

/// Closed finality vocabulary this choke point spends against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FinalityRequirement {
    /// The chain proves deterministic finality for the observed block.
    Deterministic,
    /// The chain is probabilistic and the observer must have seen at least
    /// this confirmation depth.
    Confirmations { min_depth: u64 },
}

/// Require the observation to be expressed in the regime its own policy
/// names.
///
/// A deterministic claim under a confirmation-count policy is rejected rather
/// than accepted as "stronger": that policy exists precisely because the
/// chain cannot prove finality, so the claim would be an assertion the
/// deployment already said it cannot make.
fn ensure_observed_finality_satisfies_policy(
    snapshot: &FindingFinalizedBondSnapshot,
) -> Result<(), SettlementError> {
    let requirement = parse_finality_policy(&snapshot.finality_policy)?;
    match (requirement, snapshot.observed_finality) {
        (FinalityRequirement::Deterministic, FindingObservedFinality::Finalized) => Ok(()),
        (
            FinalityRequirement::Confirmations { min_depth },
            FindingObservedFinality::Confirmations { depth },
        ) if depth >= min_depth => Ok(()),
        _ => Err(reject(
            "observed finality does not satisfy the snapshot finality policy",
        )),
    }
}

fn parse_finality_policy(policy: &str) -> Result<FinalityRequirement, SettlementError> {
    if policy == DETERMINISTIC_FINALITY_POLICY {
        return Ok(FinalityRequirement::Deterministic);
    }
    let Some(depth) = policy.strip_prefix(CONFIRMATION_FINALITY_PREFIX) else {
        return Err(reject("unrecognized bond snapshot finality policy"));
    };
    if depth.is_empty()
        || depth.starts_with('0')
        || !depth.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(reject(
            "bond snapshot finality policy carries a non-canonical confirmation depth",
        ));
    }
    let min_depth = depth
        .parse::<u64>()
        .map_err(|_| reject("bond snapshot finality policy confirmation depth is out of range"))?;
    Ok(FinalityRequirement::Confirmations { min_depth })
}

/// Re-derive the destination sum at the choke point.
///
/// The artifact validator already enforces this, and it runs first. Money
/// leaves the vault on the strength of this list, so the total is recomputed
/// here rather than inherited from an upstream validator: a short sum strands
/// slashed collateral and a long one overdraws the vault.
fn ensure_destinations_sum_exactly(
    enforcement: &FindingChallengeEnforcement,
) -> Result<(), SettlementError> {
    let mut total = 0_u64;
    for destination in &enforcement.destinations {
        if destination.amount.currency != enforcement.amount.currency {
            return Err(reject("enforcement destination currency is inconsistent"));
        }
        total = total
            .checked_add(destination.amount.units)
            .ok_or_else(|| reject("enforcement destination amounts overflowed"))?;
    }
    if total != enforcement.amount.units {
        return Err(reject(
            "enforcement destinations do not sum exactly to the enforcement amount",
        ));
    }
    Ok(())
}

fn ensure_snapshot_is_fresh(
    snapshot: &FindingFinalizedBondSnapshot,
    max_snapshot_age_secs: u64,
    trusted_now_secs: u64,
) -> Result<(), SettlementError> {
    let Some(age_secs) = trusted_now_secs.checked_sub(snapshot.observed_at) else {
        return Err(reject(
            "bond snapshot was observed after the trusted current time",
        ));
    };
    if age_secs > max_snapshot_age_secs {
        return Err(reject(
            "bond snapshot is older than the configured maximum observation age",
        ));
    }
    Ok(())
}

/// Which part of the operator qualification moved since the snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingOperatorQualification {
    /// The identity registry record naming the observing operator.
    IdentityRegistryRecord,
    /// The operator key hash bound to that record.
    OperatorKeyHash,
    /// The operator key epoch.
    OperatorKeyEpoch,
}

/// Chain and identity state re-read after the snapshot was verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingBondObservationRecheck {
    /// Block hash currently canonical at the snapshot's block number, or
    /// `None` when the chain no longer carries a block at that height.
    pub block_hash: Option<String>,
    /// Identity registry record currently naming the observing operator.
    pub identity_registry_record: String,
    /// Operator key hash currently bound to that record.
    pub operator_key_hash: String,
    /// Operator key epoch currently in force.
    pub operator_key_epoch: u64,
    /// Whether the identity registry still lists the operator as active.
    pub operator_active: bool,
}

/// Typed result of re-reading the chain and identity state behind a verified
/// snapshot.
///
/// Every non-qualified verdict returns the liability to reconciliation. None
/// of them is evidence that an impairment happened or that one is still
/// authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingBondObservationVerdict {
    /// The observed block and the operator qualification are unchanged.
    Qualified,
    /// The block the snapshot observed is no longer the canonical block at
    /// that height, so the collateral state it reported is unknown.
    Reorged {
        /// Block hash the snapshot observed.
        expected_block_hash: String,
        /// Block hash the chain now carries, or `None` when the height is
        /// gone entirely.
        observed_block_hash: Option<String>,
    },
    /// The operator identity behind the observation rotated.
    OperatorRotated {
        /// Which part of the qualification moved.
        field: FindingOperatorQualification,
    },
    /// The identity registry no longer lists the observing operator as
    /// active.
    OperatorNotActive,
}

impl FindingBondObservationVerdict {
    /// Return whether the observation still qualifies for anchoring or
    /// impairment.
    #[must_use]
    pub const fn is_qualified(&self) -> bool {
        matches!(self, Self::Qualified)
    }
}

/// Recheck the observed block hash and the operator qualification behind a
/// verified snapshot.
///
/// The coordinator runs this before anchoring and again after the impairment
/// receipt reaches finality. A reorg or a rotation is a reconciliation
/// verdict, never an assumed slash.
#[must_use]
pub fn recheck_finding_bond_observation(
    verified: &VerifiedFindingEnforcement,
    observed: &FindingBondObservationRecheck,
) -> FindingBondObservationVerdict {
    let snapshot = verified.snapshot();
    let expected_block_hash = normalize_chain_hash(&snapshot.block_hash);
    let observed_block_hash = observed.block_hash.as_deref().map(normalize_chain_hash);
    if observed_block_hash.as_deref() != Some(expected_block_hash.as_str()) {
        return FindingBondObservationVerdict::Reorged {
            expected_block_hash: snapshot.block_hash.clone(),
            observed_block_hash: observed.block_hash.clone(),
        };
    }
    if !observed.operator_active {
        return FindingBondObservationVerdict::OperatorNotActive;
    }
    if observed.identity_registry_record != snapshot.identity_registry_record {
        return FindingBondObservationVerdict::OperatorRotated {
            field: FindingOperatorQualification::IdentityRegistryRecord,
        };
    }
    if normalize_chain_hash(&observed.operator_key_hash)
        != normalize_chain_hash(&snapshot.operator_key_hash)
    {
        return FindingBondObservationVerdict::OperatorRotated {
            field: FindingOperatorQualification::OperatorKeyHash,
        };
    }
    if observed.operator_key_epoch != snapshot.operator_key_epoch {
        return FindingBondObservationVerdict::OperatorRotated {
            field: FindingOperatorQualification::OperatorKeyEpoch,
        };
    }
    FindingBondObservationVerdict::Qualified
}

/// Normalize a chain hash for comparison: the `0x` prefix is optional in the
/// artifact shape, so two renderings of the same hash must compare equal.
fn normalize_chain_hash(value: &str) -> String {
    value
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_ascii_lowercase()
}
