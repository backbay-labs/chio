//! Fail-closed verification of finding enforcement authority.

use std::collections::BTreeSet;

use chio_core::crypto::{PublicKey, SigningAlgorithm};
use chio_finding::{
    signed_envelope_sha256, verify_pinned_envelope, verify_signed_authority_status,
    verify_signed_challenge_enforcement, verify_signed_finalized_bond_snapshot,
    FindingChallengeEnforcement, FindingEffectIntentKind, FindingFinalizedBondSnapshot,
    FindingObservedFinality, SignedFindingAuthorityStatus, SignedFindingChallengeEnforcement,
    SignedFindingFinalizedBondSnapshot, FINDING_AUTHORITY_STATUS_SCHEMA_V1,
};
use chio_open_market::evidence::OpenMarketEvidenceKind;
use chio_open_market::fee_schedule::OpenMarketBondClass;
use chio_open_market::penalty::{
    OpenMarketAbuseClass, OpenMarketPenaltyAction, OpenMarketPenaltyState, SignedOpenMarketPenalty,
};

use super::{parse_evm_address, reject};
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
    /// Chain finality the deployment requires before collateral may be
    /// impaired. This is operator configuration, never a value selected by
    /// the observer signing the snapshot.
    pub finality_requirement: FindingFinalityRequirement,
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
        self.finality_requirement.validate()?;
        Ok(())
    }
}

/// Independently pinned policy required only when an enforcement can create a
/// new dispatch. Reconciliation carries no such authority and therefore does
/// not depend on a later mutable policy reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingDispatchPolicy {
    /// Independently retained lifecycle policy that assigned the penalty
    /// signer its role. This must come from durable governance state keyed by
    /// the presented penalty envelope, never from the enforcement itself.
    pub penalty_authority: FindingPenaltyAuthorityPolicy,
    /// Independent authority that signs revocation-source readings for the
    /// historical penalty key named by the enforcement.
    pub authority_status_authority: PublicKey,
    /// Oldest authenticated penalty-authority status reading this choke point
    /// accepts, in seconds.
    pub max_authority_status_age_secs: u64,
    /// Operator policy for destinations that may receive impaired collateral.
    /// The coordinator derives this set from durable payout admissions rather
    /// than from the enforcement being verified.
    pub allowed_destinations: BTreeSet<String>,
}

/// Durable governance assignment for the penalty signer used by one
/// dispatch. The enforcement repeats these fields for historical
/// reproducibility, but only exact equality with this retained policy grants
/// the key its penalty role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingPenaltyAuthorityPolicy {
    pub authority_id: String,
    pub key: PublicKey,
    pub key_epoch: u64,
    pub valid_from: u64,
    pub valid_until: u64,
    pub revocation_status_ref: String,
}

impl FindingPenaltyAuthorityPolicy {
    fn validate(&self) -> Result<(), SettlementError> {
        if self.authority_id.trim().is_empty() {
            return Err(SettlementError::InvalidInput(
                "penalty authority id must be non-empty".to_owned(),
            ));
        }
        require_signing_key(&self.key, "penalty_authority")?;
        if self.key_epoch == 0 {
            return Err(SettlementError::InvalidInput(
                "penalty authority key epoch must be nonzero".to_owned(),
            ));
        }
        if self.valid_until <= self.valid_from {
            return Err(SettlementError::InvalidInput(
                "penalty authority validity window is inverted".to_owned(),
            ));
        }
        if self.revocation_status_ref.trim().is_empty() {
            return Err(SettlementError::InvalidInput(
                "penalty authority revocation status ref must be non-empty".to_owned(),
            ));
        }
        Ok(())
    }
}

impl FindingDispatchPolicy {
    /// Reject unusable status and destination policy before any artifact can
    /// inherit dispatch authority from it.
    pub fn validate(&self, pins: &FindingEnforcementPins) -> Result<(), SettlementError> {
        self.penalty_authority.validate()?;
        require_signing_key(
            &self.authority_status_authority,
            "authority_status_authority",
        )?;
        if self.authority_status_authority == self.penalty_authority.key {
            return Err(SettlementError::InvalidInput(
                "authority_status_authority and penalty_authority must be distinct keys".to_owned(),
            ));
        }
        for (other, label) in [
            (
                &pins.finalization_authority,
                "authority_status_authority and finalization_authority",
            ),
            (
                &pins.settlement_observer,
                "authority_status_authority and settlement_observer",
            ),
            (&pins.seller, "authority_status_authority and seller"),
        ] {
            if &self.authority_status_authority == other {
                return Err(SettlementError::InvalidInput(format!(
                    "{label} must be distinct keys"
                )));
            }
        }
        if self.max_authority_status_age_secs == 0 {
            return Err(SettlementError::InvalidInput(
                "max_authority_status_age_secs must be nonzero".to_string(),
            ));
        }
        if self.allowed_destinations.is_empty() {
            return Err(SettlementError::InvalidInput(
                "allowed_destinations must not be empty".to_string(),
            ));
        }
        let mut normalized_destinations = BTreeSet::new();
        for destination in &self.allowed_destinations {
            let parsed = parse_evm_address(destination, "allowed_destinations")?;
            if !normalized_destinations.insert(parsed) {
                return Err(SettlementError::InvalidInput(
                    "allowed_destinations contains the same address more than once".to_string(),
                ));
            }
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
    root_intent_id: String,
    finality_requirement: FindingFinalityRequirement,
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

    /// Domain-keyed identity of the enforcement-root effect.
    ///
    /// The vault verifies the impairment against a published root, so this
    /// intent has to be confirmed before the call is broadcast. The
    /// instruction names it; whether it was published is durable state the
    /// coordinator holds.
    #[must_use]
    pub fn root_intent_id(&self) -> &str {
        &self.root_intent_id
    }

    /// Deployment-pinned finality requirement authenticated with the pair.
    #[must_use]
    pub const fn finality_requirement(&self) -> FindingFinalityRequirement {
        self.finality_requirement
    }
}

/// A previously dispatched enforcement authenticated for reconciliation.
///
/// This capability deliberately cannot be passed to
/// [`plan_finding_impairment`](super::plan_finding_impairment). Recovery may
/// use an aged snapshot to reconstruct and re-observe the exact frozen call,
/// but it cannot turn that historical observation into fresh dispatch
/// authority.
#[derive(Debug, Clone)]
pub struct ReconciledFindingEnforcement {
    verified: VerifiedFindingEnforcement,
}

impl ReconciledFindingEnforcement {
    /// The authenticated enforcement instruction body.
    #[must_use]
    pub const fn enforcement(&self) -> &FindingChallengeEnforcement {
        self.verified.enforcement()
    }

    /// Domain-keyed identity of the seller-impairment effect.
    #[must_use]
    pub fn seller_impair_intent_id(&self) -> &str {
        self.verified.seller_impair_intent_id()
    }

    /// Domain-keyed identity of the enforcement-root effect.
    #[must_use]
    pub fn root_intent_id(&self) -> &str {
        self.verified.root_intent_id()
    }

    pub(super) const fn verified(&self) -> &VerifiedFindingEnforcement {
        &self.verified
    }
}

/// Verify one enforcement instruction against its penalty, historical
/// lifecycle witness, destination policy, and bound bond snapshot.
///
/// `trusted_now_secs` is supplied by the caller because this crate owns no
/// clock. It must come from the coordinator's trusted time source, not from
/// any artifact: a snapshot or status witness that dated itself would
/// otherwise certify its own freshness.
pub fn verify_finding_enforcement(
    signed_enforcement: &SignedFindingChallengeEnforcement,
    signed_penalty: &SignedOpenMarketPenalty,
    penalty_authority_status: &SignedFindingAuthorityStatus,
    signed_snapshot: &SignedFindingFinalizedBondSnapshot,
    pins: &FindingEnforcementPins,
    dispatch_policy: &FindingDispatchPolicy,
    trusted_now_secs: u64,
) -> Result<VerifiedFindingEnforcement, SettlementError> {
    verify_finding_enforcement_inner(
        signed_enforcement,
        signed_snapshot,
        pins,
        trusted_now_secs,
        true,
        Some((signed_penalty, penalty_authority_status, dispatch_policy)),
    )
}

/// Authenticate the live collateral input used to size a finding penalty.
///
/// The coordinator separately binds the returned snapshot body to the
/// admitted allocation and currency. This function establishes the observer
/// signature, pinned finality policy, freshness, and checked live balance so
/// no bare request number can enter the penalty calculation.
pub fn verify_finding_collateral_snapshot(
    signed_snapshot: &SignedFindingFinalizedBondSnapshot,
    settlement_observer: &PublicKey,
    finality_requirement: FindingFinalityRequirement,
    max_snapshot_age_secs: u64,
    trusted_now_secs: u64,
) -> Result<u64, SettlementError> {
    verify_signed_finalized_bond_snapshot(signed_snapshot, settlement_observer)
        .map_err(|error| reject(format!("finalized bond snapshot rejected: {error}")))?;
    ensure_observed_finality_satisfies_policy(&signed_snapshot.body, finality_requirement)?;
    ensure_snapshot_is_fresh(
        &signed_snapshot.body,
        max_snapshot_age_secs,
        trusted_now_secs,
    )?;
    signed_snapshot
        .body
        .live_allocated_collateral()
        .map_err(|error| {
            reject(format!(
                "bond snapshot collateral is not computable: {error}"
            ))
        })
}

/// Verify a previously dispatched enforcement for post-dispatch recovery.
///
/// Once the exact seller impairment is durably confirmed, an aged
/// pre-dispatch snapshot cannot authorize another dispatch. Recovery still
/// authenticates and binds that snapshot, rejects a future observation, and
/// lets the caller re-read its block and operator qualification before
/// clearing quarantine.
pub fn verify_finding_enforcement_for_reconciliation(
    signed_enforcement: &SignedFindingChallengeEnforcement,
    signed_snapshot: &SignedFindingFinalizedBondSnapshot,
    pins: &FindingEnforcementPins,
    trusted_now_secs: u64,
) -> Result<ReconciledFindingEnforcement, SettlementError> {
    verify_finding_enforcement_inner(
        signed_enforcement,
        signed_snapshot,
        pins,
        trusted_now_secs,
        false,
        None,
    )
    .map(|verified| ReconciledFindingEnforcement { verified })
}

fn verify_finding_enforcement_inner(
    signed_enforcement: &SignedFindingChallengeEnforcement,
    signed_snapshot: &SignedFindingFinalizedBondSnapshot,
    pins: &FindingEnforcementPins,
    trusted_now_secs: u64,
    require_fresh_snapshot: bool,
    penalty_evidence: Option<(
        &SignedOpenMarketPenalty,
        &SignedFindingAuthorityStatus,
        &FindingDispatchPolicy,
    )>,
) -> Result<VerifiedFindingEnforcement, SettlementError> {
    pins.validate()?;

    verify_signed_challenge_enforcement(signed_enforcement, &pins.finalization_authority)
        .map_err(|error| reject(format!("challenge enforcement rejected: {error}")))?;
    verify_signed_finalized_bond_snapshot(signed_snapshot, &pins.settlement_observer)
        .map_err(|error| reject(format!("finalized bond snapshot rejected: {error}")))?;

    let enforcement = &signed_enforcement.body;
    let snapshot = &signed_snapshot.body;

    if let Some((signed_penalty, penalty_authority_status, dispatch_policy)) = penalty_evidence {
        dispatch_policy.validate(pins)?;
        verify_penalty_dispatch_authority(
            enforcement,
            signed_penalty,
            penalty_authority_status,
            dispatch_policy,
            trusted_now_secs,
        )?;
        ensure_destinations_allowed(enforcement, &dispatch_policy.allowed_destinations)?;
    }

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

    ensure_observed_finality_satisfies_policy(snapshot, pins.finality_requirement)?;

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
    ensure_snapshot_is_not_from_future(snapshot, trusted_now_secs)?;
    if require_fresh_snapshot {
        ensure_snapshot_is_fresh(snapshot, pins.max_snapshot_age_secs, trusted_now_secs)?;
    }

    let seller_impair_intent_id =
        bound_intent_id(enforcement, FindingEffectIntentKind::SellerImpair)
            .ok_or_else(|| reject("enforcement carries no seller-impairment effect intent"))?;
    let root_intent_id = bound_intent_id(enforcement, FindingEffectIntentKind::RootIntent)
        .ok_or_else(|| reject("enforcement carries no enforcement-root effect intent"))?;

    Ok(VerifiedFindingEnforcement {
        enforcement: enforcement.clone(),
        snapshot: snapshot.clone(),
        enforcement_envelope_sha256,
        bond_snapshot_envelope_sha256,
        live_allocated_collateral,
        seller_impair_intent_id,
        root_intent_id,
        finality_requirement: pins.finality_requirement,
    })
}

/// Authenticate the exact penalty and historical authority lifecycle that
/// make an enforcement dispatchable.
fn verify_penalty_dispatch_authority(
    enforcement: &FindingChallengeEnforcement,
    signed_penalty: &SignedOpenMarketPenalty,
    penalty_authority_status: &SignedFindingAuthorityStatus,
    dispatch_policy: &FindingDispatchPolicy,
    trusted_now_secs: u64,
) -> Result<(), SettlementError> {
    let retained = &dispatch_policy.penalty_authority;
    if enforcement.penalty_authority_id != retained.authority_id
        || enforcement.penalty_key != retained.key
        || enforcement.penalty_key_epoch != retained.key_epoch
        || enforcement.penalty_valid_from != retained.valid_from
        || enforcement.penalty_valid_until != retained.valid_until
        || enforcement.penalty_revocation_status_ref != retained.revocation_status_ref
    {
        return Err(reject(
            "enforcement penalty authority does not match retained governance policy",
        ));
    }
    signed_penalty
        .body
        .validate()
        .map_err(|error| reject(format!("market penalty rejected: {error}")))?;
    verify_pinned_envelope(signed_penalty, &enforcement.penalty_key, "market penalty")
        .map_err(|error| reject(format!("market penalty rejected: {error}")))?;
    let penalty_digest = signed_envelope_sha256(signed_penalty)
        .map_err(|error| reject(format!("market penalty envelope digest failed: {error}")))?;
    if penalty_digest != enforcement.penalty_envelope_sha256 {
        return Err(reject(
            "enforcement penalty_envelope_sha256 does not bind the presented penalty",
        ));
    }
    let penalty = &signed_penalty.body;
    if penalty.listing_id != enforcement.listing_id
        || penalty.bond_class != OpenMarketBondClass::Listing
        || penalty.abuse_class != OpenMarketAbuseClass::FraudulentListing
        || penalty.action != OpenMarketPenaltyAction::SlashBond
        || penalty.state != OpenMarketPenaltyState::Enforced
        || penalty.penalty_amount != enforcement.amount
    {
        return Err(reject(
            "presented penalty does not authorize this enforcement",
        ));
    }
    let [evidence] = penalty.evidence_refs.as_slice() else {
        return Err(reject(
            "finding penalty must carry exactly one challenge-outcome reference",
        ));
    };
    if evidence.kind != OpenMarketEvidenceKind::External
        || evidence.reference_id != enforcement.outcome_id
        || evidence.sha256.as_deref() != Some(enforcement.outcome_envelope_sha256.as_str())
    {
        return Err(reject(
            "finding penalty does not bind the adjudicated challenge outcome",
        ));
    }
    if penalty.updated_at < enforcement.penalty_valid_from
        || penalty.updated_at >= enforcement.penalty_valid_until
    {
        return Err(reject(
            "market penalty was signed outside its historical authority window",
        ));
    }
    if penalty
        .expires_at
        .is_some_and(|expires_at| expires_at <= trusted_now_secs)
    {
        return Err(reject("market penalty expired before dispatch"));
    }

    verify_signed_authority_status(
        penalty_authority_status,
        &dispatch_policy.authority_status_authority,
    )
    .map_err(|error| reject(format!("penalty authority status rejected: {error}")))?;
    let status = &penalty_authority_status.body;
    if status.schema != FINDING_AUTHORITY_STATUS_SCHEMA_V1
        || status.status_ref != enforcement.penalty_revocation_status_ref
        || status.authority_id != enforcement.penalty_authority_id
        || status.key != enforcement.penalty_key
        || status.key_epoch != enforcement.penalty_key_epoch
    {
        return Err(reject(
            "penalty authority status does not bind the historical policy",
        ));
    }
    if status.observed_at < penalty.updated_at || status.observed_at > trusted_now_secs {
        return Err(reject(
            "penalty authority status is not a post-action trusted-time reading",
        ));
    }
    if trusted_now_secs.saturating_sub(status.observed_at)
        > dispatch_policy.max_authority_status_age_secs
    {
        return Err(reject(
            "penalty authority status is older than the configured maximum age",
        ));
    }
    if status
        .revoked_from
        .is_some_and(|revoked_from| revoked_from <= penalty.updated_at)
    {
        return Err(reject(
            "penalty authority was revoked when the penalty was signed",
        ));
    }
    Ok(())
}

/// Apply the independently derived operator policy to every destination that
/// the verified enforcement would send to the vault.
fn ensure_destinations_allowed(
    enforcement: &FindingChallengeEnforcement,
    allowed_destinations: &BTreeSet<String>,
) -> Result<(), SettlementError> {
    let allowed = allowed_destinations
        .iter()
        .map(|destination| parse_evm_address(destination, "allowed_destinations"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    for destination in &enforcement.destinations {
        let parsed = parse_evm_address(
            &destination.destination,
            "finding impairment enforcement destination",
        )?;
        if !allowed.contains(&parsed) {
            return Err(reject(
                "finding impairment enforcement destination is not operator-allowlisted",
            ));
        }
    }
    Ok(())
}

/// The single intent id an enforcement binds for one effect kind.
///
/// A duplicate binding is not a preference to resolve: two ids for one
/// effect mean the instruction does not say which intent fences it, so the
/// pair is refused rather than read as naming the first.
fn bound_intent_id(
    enforcement: &FindingChallengeEnforcement,
    kind: FindingEffectIntentKind,
) -> Option<String> {
    let mut bound = enforcement
        .effect_intents
        .iter()
        .filter(|intent| intent.kind == kind);
    let first = bound.next()?;
    if bound.next().is_some() {
        return None;
    }
    Some(first.intent_id.clone())
}

/// Externally pinned chain finality this choke point spends against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingFinalityRequirement {
    /// The chain proves deterministic finality for the observed block.
    Deterministic,
    /// The chain is probabilistic and the observer must have seen at least
    /// this confirmation depth.
    Confirmations { min_depth: u64 },
}

impl FindingFinalityRequirement {
    /// Reject a deployment policy that cannot establish finality.
    pub fn validate(self) -> Result<(), SettlementError> {
        if matches!(self, Self::Confirmations { min_depth: 0 }) {
            return Err(SettlementError::InvalidInput(
                "finding finality confirmation depth must be nonzero".to_string(),
            ));
        }
        Ok(())
    }
}

/// Require the observer's declaration and observation to satisfy the policy
/// pinned by the deployment.
///
/// A deterministic claim under a confirmation-count policy is rejected rather
/// than accepted as "stronger": that policy exists precisely because the
/// chain cannot prove finality, so the claim would be an assertion the
/// deployment already said it cannot make.
fn ensure_observed_finality_satisfies_policy(
    snapshot: &FindingFinalizedBondSnapshot,
    requirement: FindingFinalityRequirement,
) -> Result<(), SettlementError> {
    let declared = parse_finality_policy(&snapshot.finality_policy)?;
    if declared != requirement {
        return Err(reject(
            "bond snapshot finality policy does not match the pinned finality requirement",
        ));
    }
    if observed_finality_satisfies(requirement, snapshot.observed_finality) {
        Ok(())
    } else {
        Err(reject(
            "observed finality does not satisfy the snapshot finality policy",
        ))
    }
}

const fn observed_finality_satisfies(
    requirement: FindingFinalityRequirement,
    observed: FindingObservedFinality,
) -> bool {
    match (requirement, observed) {
        (FindingFinalityRequirement::Deterministic, FindingObservedFinality::Finalized) => true,
        (
            FindingFinalityRequirement::Confirmations { min_depth },
            FindingObservedFinality::Confirmations { depth },
        ) => depth >= min_depth,
        _ => false,
    }
}

fn parse_finality_policy(policy: &str) -> Result<FindingFinalityRequirement, SettlementError> {
    if policy == DETERMINISTIC_FINALITY_POLICY {
        return Ok(FindingFinalityRequirement::Deterministic);
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
    Ok(FindingFinalityRequirement::Confirmations { min_depth })
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
    let age_secs = trusted_now_secs
        .checked_sub(snapshot.observed_at)
        .ok_or_else(|| reject("bond snapshot was observed after the trusted current time"))?;
    if age_secs > max_snapshot_age_secs {
        return Err(reject(
            "bond snapshot is older than the configured maximum observation age",
        ));
    }
    Ok(())
}

fn ensure_snapshot_is_not_from_future(
    snapshot: &FindingFinalizedBondSnapshot,
    trusted_now_secs: u64,
) -> Result<(), SettlementError> {
    if trusted_now_secs.checked_sub(snapshot.observed_at).is_none() {
        return Err(reject(
            "bond snapshot was observed after the trusted current time",
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
    /// Current finality assessment for that same canonical block.
    pub observed_finality: FindingObservedFinality,
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
    /// The block remains canonical but no longer meets the deployment's
    /// pinned finality requirement.
    FinalityRegressed {
        required: FindingFinalityRequirement,
        observed: FindingObservedFinality,
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

    /// A stable one-line reason a caller can report a refusal with.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Qualified => "observation still qualifies",
            Self::Reorged { .. } => "the block the bond snapshot observed is no longer canonical",
            Self::FinalityRegressed { .. } => {
                "the bond snapshot block no longer meets the pinned finality requirement"
            }
            Self::OperatorRotated {
                field: FindingOperatorQualification::IdentityRegistryRecord,
            } => "the identity registry record behind the observation changed",
            Self::OperatorRotated {
                field: FindingOperatorQualification::OperatorKeyHash,
            } => "the operator key hash behind the observation rotated",
            Self::OperatorRotated {
                field: FindingOperatorQualification::OperatorKeyEpoch,
            } => "the operator key epoch behind the observation advanced",
            Self::OperatorNotActive => {
                "the identity registry no longer lists the observing operator as active"
            }
        }
    }
}

/// Live re-read of the chain and identity state one verified snapshot rests
/// on.
///
/// The trait is dyn-compatible so a coordinator can hold an
/// `Arc<dyn FindingBondObservationSource>`. It exists because the recheck has
/// to run twice against genuinely different reads: once before the impairment
/// is planned, and once after its receipt has finalized. Handing the same
/// captured observation to both would make the second check vacuous, which is
/// exactly the window a reorg lands in.
///
/// Implementations read the chain and the identity registry. This crate opens
/// no sockets and ships no adapter.
pub trait FindingBondObservationSource: Send + Sync {
    /// Read the state currently behind the verified snapshot.
    ///
    /// An implementation that cannot complete the read returns an error
    /// rather than a stale or partial observation: unknown chain state must
    /// deny, never qualify.
    fn observe(
        &self,
        verified: &VerifiedFindingEnforcement,
    ) -> Result<FindingBondObservationRecheck, SettlementError>;
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
    let required = verified.finality_requirement();
    if !observed_finality_satisfies(required, observed.observed_finality) {
        return FindingBondObservationVerdict::FinalityRegressed {
            required,
            observed: observed.observed_finality,
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
