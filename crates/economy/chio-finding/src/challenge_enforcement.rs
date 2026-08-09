//! `chio.finding.challenge-enforcement.v1`: the venue finalization
//! authority's signed instruction to impair one seller allocation.
//!
//! This artifact plus the finalized bond snapshot are the whole
//! finding-specific settlement authorization. It freezes the liability, the
//! exact outcome and penalty envelopes, the sealed purchase snapshot and its
//! deterministic allocation, the vault, the amount, the ordered
//! destinations, and the sequence-independent semantic effect intents.
//!
//! Publisher-only state is excluded BY CONSTRUCTION: there is no member for
//! an assigned operator sequence, an attempt key, prepared calldata, or a
//! transaction nonce. Those values are chosen after this artifact is signed,
//! when the publisher acquires the strict-next sequence lease, and a
//! signature over them would either force a re-signature per attempt or
//! freeze a nonce the chain has already moved past. The attempt key derives
//! from the root intent id and the assigned sequence at publication time
//! instead.
//!
//! The destination list is ordered and its amounts sum EXACTLY to the total.
//! Exact-sum checking alone does not prove harmed-party destinations; the
//! settlement choke point applies the operator policy allowlist on top.

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::envelope::require_ed25519;
use crate::finalized_bond_snapshot::FindingVaultReference;
use crate::validate::{
    require_bounded_id, require_currency, require_hex64, require_nonzero, require_window,
    FindingError,
};

/// Venue-finalization-authority-signed enforcement instruction.
pub const FINDING_CHALLENGE_ENFORCEMENT_SCHEMA_V1: &str =
    chio_core_types::signed_artifact::CHIO_FINDING_CHALLENGE_ENFORCEMENT_V1_SCHEMA;

/// Bound on the unbatched v1 destination list: fifteen distinct buyer
/// destinations plus the pinned community fund.
pub const MAX_ENFORCEMENT_DESTINATIONS: usize = 16;

/// Domain-keyed semantic effects. Each intent has its own identity so a
/// retry of one effect can never reconcile against another, and a single
/// coarse liability key cannot collapse them.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingEffectIntentKind {
    /// The single unbatched seller impairment and payout.
    SellerImpair,
    /// The buyer challenge-lock disposition.
    ChallengeBond,
    /// Dispute-fee or audit-cost reimbursement.
    Fee,
    /// The enforcement/root semantic intent that is anchored before
    /// impairment.
    RootIntent,
    /// The status-feed retraction, durably enqueued but dispatch-ineligible
    /// until impairment is confirmed final.
    Retraction,
}

impl FindingEffectIntentKind {
    /// Intents that must exist before any external impairment: the root
    /// anchor, the impairment itself, and the retraction that must not be
    /// lost if the process dies mid-flight.
    pub const REQUIRED: [FindingEffectIntentKind; 3] = [
        FindingEffectIntentKind::SellerImpair,
        FindingEffectIntentKind::RootIntent,
        FindingEffectIntentKind::Retraction,
    ];
}

/// One durable semantic intent, named by its domain-keyed digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingEffectIntentBinding {
    pub kind: FindingEffectIntentKind,
    pub intent_id: String,
}

/// One ordered payout destination and its share.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingEnforcementDestination {
    /// Immutable rail-tagged destination, taken from the authoritative
    /// purchase index or the admission-pinned community fund. A
    /// challenge-supplied or freshly resolved address is never admissible.
    pub destination: String,
    pub amount: MonetaryAmount,
}

/// Enforcement instruction body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingChallengeEnforcement {
    pub schema: String,
    /// Content-addressed: sha256 of the canonical body with
    /// `enforcement_id` cleared.
    pub enforcement_id: String,
    /// The one liability this enforcement settles. A second corroborating
    /// challenge maps to the same key and cannot authorize a second slash.
    pub liability_key: String,
    pub finding_id: String,
    pub listing_id: String,
    pub outcome_id: String,
    pub outcome_envelope_sha256: String,
    pub penalty_envelope_sha256: String,
    pub bond_snapshot_envelope_sha256: String,
    pub purchase_snapshot_digest: String,
    pub deterministic_allocation_digest: String,
    pub seller_allocation_id: String,
    pub vault: FindingVaultReference,
    pub amount: MonetaryAmount,
    /// Ordered by the deterministic allocation; the amounts sum exactly to
    /// `amount`.
    pub destinations: Vec<FindingEnforcementDestination>,
    pub effect_intents: Vec<FindingEffectIntentBinding>,
    /// Exact historical lifecycle policy that authorized this signature.
    /// Recovery resolves this policy after deployment rotation instead of
    /// verifying an old enforcement under the current key.
    pub finalization_authority_id: String,
    pub finalization_key: PublicKey,
    pub finalization_key_epoch: u64,
    pub finalization_valid_from: u64,
    pub finalization_valid_until: u64,
    pub finalization_revocation_status_ref: String,
    pub finalized_at: u64,
}

/// Venue-finalization-authority-signed envelope for the enforcement.
pub type SignedFindingChallengeEnforcement = SignedExportEnvelope<FindingChallengeEnforcement>;

impl FindingChallengeEnforcement {
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_CHALLENGE_ENFORCEMENT_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.enforcement_id, "enforcement_id")?;
        require_hex64(&self.liability_key, "liability_key")?;
        require_hex64(&self.finding_id, "finding_id")?;
        require_bounded_id(&self.listing_id, "listing_id")?;
        require_hex64(&self.outcome_id, "outcome_id")?;
        require_hex64(&self.outcome_envelope_sha256, "outcome_envelope_sha256")?;
        require_hex64(&self.penalty_envelope_sha256, "penalty_envelope_sha256")?;
        require_hex64(
            &self.bond_snapshot_envelope_sha256,
            "bond_snapshot_envelope_sha256",
        )?;
        require_hex64(&self.purchase_snapshot_digest, "purchase_snapshot_digest")?;
        require_hex64(
            &self.deterministic_allocation_digest,
            "deterministic_allocation_digest",
        )?;
        require_hex64(&self.seller_allocation_id, "seller_allocation_id")?;
        self.vault.validate()?;
        require_nonzero(self.amount.units, "amount")?;
        require_currency(&self.amount.currency, "amount.currency")?;
        self.validate_destinations()?;
        self.validate_effect_intents()?;
        require_bounded_id(&self.finalization_authority_id, "finalization_authority_id")?;
        require_ed25519(&self.finalization_key, "finalization_key")?;
        require_nonzero(self.finalization_key_epoch, "finalization_key_epoch")?;
        require_window(
            self.finalization_valid_from,
            self.finalization_valid_until,
            "finalization_valid_from",
            "finalization_valid_until",
        )?;
        require_bounded_id(
            &self.finalization_revocation_status_ref,
            "finalization_revocation_status_ref",
        )?;
        require_nonzero(self.finalized_at, "finalized_at")?;
        if self.finalized_at < self.finalization_valid_from
            || self.finalized_at >= self.finalization_valid_until
        {
            return Err(FindingError::InvalidField("finalized_at"));
        }
        self.verify_enforcement_id()
    }

    /// Every destination is distinct, carries a nonzero share in the one
    /// enforcement currency, and the shares sum EXACTLY to the total. A
    /// short sum would strand slashed collateral and a long one would
    /// overdraw the vault, so neither is tolerated.
    fn validate_destinations(&self) -> Result<(), FindingError> {
        if self.destinations.is_empty() {
            return Err(FindingError::MissingEntry("destinations"));
        }
        if self.destinations.len() > MAX_ENFORCEMENT_DESTINATIONS {
            return Err(FindingError::SizeLimitExceeded("destinations"));
        }
        let mut seen = BTreeSet::new();
        let mut total = 0_u64;
        for entry in &self.destinations {
            require_bounded_id(&entry.destination, "destinations[].destination")?;
            require_nonzero(entry.amount.units, "destinations[].amount")?;
            if entry.amount.currency != self.amount.currency {
                return Err(FindingError::CurrencyMismatch("destinations[]"));
            }
            if !seen.insert(entry.destination.as_str()) {
                return Err(FindingError::DuplicateEntry("destinations[]"));
            }
            total = total
                .checked_add(entry.amount.units)
                .ok_or(FindingError::AmountOverflow("destinations"))?;
        }
        if total != self.amount.units {
            return Err(FindingError::InvalidField("destinations"));
        }
        Ok(())
    }

    /// Exactly one intent per kind, and every intent that must be durable
    /// before an external impairment is present.
    fn validate_effect_intents(&self) -> Result<(), FindingError> {
        let mut kinds = BTreeSet::new();
        for intent in &self.effect_intents {
            require_hex64(&intent.intent_id, "effect_intents[].intent_id")?;
            if !kinds.insert(intent.kind) {
                return Err(FindingError::DuplicateEntry("effect_intents[]"));
            }
        }
        for required in FindingEffectIntentKind::REQUIRED {
            if !kinds.contains(&required) {
                return Err(FindingError::MissingEntry("effect_intents[]"));
            }
        }
        Ok(())
    }

    /// Recompute and compare the content-addressed enforcement id.
    pub fn verify_enforcement_id(&self) -> Result<(), FindingError> {
        let expected = compute_enforcement_id(self)?;
        if expected == self.enforcement_id {
            Ok(())
        } else {
            Err(FindingError::ArtifactIdMismatch("enforcement_id"))
        }
    }
}

/// Content-addressed enforcement id: sha256 over the canonical body with
/// `enforcement_id` cleared.
pub fn compute_enforcement_id(
    enforcement: &FindingChallengeEnforcement,
) -> Result<String, FindingError> {
    let mut body = enforcement.clone();
    body.enforcement_id = String::new();
    let bytes =
        chio_core_types::canonical_json_bytes(&body).map_err(|_| FindingError::Canonicalization)?;
    Ok(chio_core_types::crypto::sha256_hex(&bytes))
}

/// Verify a signed enforcement against the externally pinned venue
/// finalization authority. That role is disjoint from the evaluator: the key
/// that signed the outcome must not be able to authorize its own
/// enforcement.
pub fn verify_signed_challenge_enforcement(
    signed: &SignedFindingChallengeEnforcement,
    pinned_finalization_authority: &PublicKey,
) -> Result<(), FindingError> {
    signed.body.validate()?;
    crate::envelope::verify_pinned_envelope(
        signed,
        pinned_finalization_authority,
        "challenge_enforcement",
    )
}
