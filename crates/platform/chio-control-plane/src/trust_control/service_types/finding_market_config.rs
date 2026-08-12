//! Deployment-pinned authority roster for the cognition-market finding
//! surfaces.
//!
//! Every value-moving role is pinned here, independently of whatever keys
//! artifacts embed: an envelope verifies only against its configured role,
//! and the body authority must equal that pin. Fail-closed at load: a
//! missing role, unparseable or weak key, noncanonical key encoding,
//! identical pool principals, or an inverted validity window rejects the
//! whole configuration.

use chio_core::crypto::{PublicKey, SigningAlgorithm};
use chio_finding::{
    FindingAuthorityKeyPolicy, FindingStatusOperatorAuthorization, FindingStatusOperatorRole,
};
use chio_settle::FindingFinalityRequirement;
use serde::{Deserialize, Serialize};

use crate::CliError;

const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;
pub(crate) const FINDING_STATUS_MAX_EPOCH_AGE_SECS: u64 = I_JSON_MAX_SAFE_INTEGER;

/// Fixed numeric key domain for `chio.finding.status.v1`.
///
/// This is the first 53 bits of SHA-256 over the protocol domain. It is a
/// selected wire constant, not a value deployments or callers may derive or
/// replace. Keeping it below 2^53 preserves the same integer in every strict
/// I-JSON implementation.
pub const FINDING_STATUS_KEY_DOMAIN_NONCE: u64 = 3_318_287_169_837_494;

/// Exact role carried by the governance-pinned status operator
/// authorization.
pub const FINDING_STATUS_OPERATOR_ROLE: &str = "finding_status_operator";

/// One pinned authority key with its lifecycle policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingAuthorityPin {
    pub authority_id: String,
    /// Canonical bare lowercase Ed25519 key hex.
    pub key_hex: String,
    pub key_epoch: u64,
    pub valid_from: u64,
    pub valid_until: u64,
    pub revocation_status_ref: String,
}

impl FindingAuthorityPin {
    pub(crate) fn validate(&self, label: &str) -> Result<PublicKey, CliError> {
        if self.authority_id.trim().is_empty() {
            return Err(CliError::cli_other_error(format!(
                "finding-market {label} authority id must be non-empty"
            )));
        }
        let key = PublicKey::from_hex(&self.key_hex).map_err(|_| {
            CliError::cli_other_error(format!("finding-market {label} key is not valid"))
        })?;
        if key.algorithm() != SigningAlgorithm::Ed25519
            || key.is_weak_ed25519()
            || key.to_hex() != self.key_hex
        {
            return Err(CliError::cli_other_error(format!(
                "finding-market {label} key must be a canonical, non-weak Ed25519 key"
            )));
        }
        if self.key_epoch == 0 {
            return Err(CliError::cli_other_error(format!(
                "finding-market {label} key epoch must be nonzero"
            )));
        }
        if self.key_epoch > I_JSON_MAX_SAFE_INTEGER
            || self.valid_from > I_JSON_MAX_SAFE_INTEGER
            || self.valid_until > I_JSON_MAX_SAFE_INTEGER
        {
            return Err(CliError::cli_other_error(format!(
                "finding-market {label} lifecycle values must be I-JSON integers"
            )));
        }
        if self.valid_until <= self.valid_from {
            return Err(CliError::cli_other_error(format!(
                "finding-market {label} validity window is inverted"
            )));
        }
        if self.revocation_status_ref.trim().is_empty() {
            return Err(CliError::cli_other_error(format!(
                "finding-market {label} revocation status ref must be non-empty"
            )));
        }
        Ok(key)
    }

    /// The parsed pinned key. Only meaningful after `validate` accepted
    /// the enclosing configuration; parse failures afterward still deny.
    pub fn key(&self) -> Result<PublicKey, CliError> {
        PublicKey::from_hex(&self.key_hex)
            .map_err(|_| CliError::cli_other_error("pinned finding-market key is not valid"))
    }

    /// Whether this role's configured validity window covers `now`.
    ///
    /// The upper bound is exclusive: a key stops being usable at the
    /// instant it expires rather than one tick after it, so a role whose
    /// window has run out signs nothing at that instant either.
    #[must_use]
    pub const fn covers(&self, now: u64) -> bool {
        now >= self.valid_from && now < self.valid_until
    }
}

/// One governance-pinned pool identity with its rail-tagged destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingPoolPin {
    pub principal_id: String,
    pub rail_destination: String,
    pub currency: String,
    pub authority_epoch: u64,
}

impl FindingPoolPin {
    fn validate(&self, label: &str) -> Result<(), CliError> {
        if self.principal_id.trim().is_empty() || self.rail_destination.trim().is_empty() {
            return Err(CliError::cli_other_error(format!(
                "finding-market {label} pool principal and destination must be non-empty"
            )));
        }
        if self.currency.len() != 3 || !self.currency.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(CliError::cli_other_error(format!(
                "finding-market {label} pool currency must be a three-letter uppercase code"
            )));
        }
        if self.authority_epoch == 0 {
            return Err(CliError::cli_other_error(format!(
                "finding-market {label} pool authority epoch must be nonzero"
            )));
        }
        Ok(())
    }
}

/// Governance-pinned authorization for one finding-status feed operator.
///
/// Rotation replaces `authority` with a higher key epoch under the same
/// `feed_id` and `rotation_policy_ref`. The durable feed floor is keyed by the
/// stable feed identity and therefore cannot reset when the authorized key
/// rotates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingStatusOperatorPin {
    pub feed_id: String,
    pub role: String,
    pub authority: FindingAuthorityPin,
    pub rotation_policy_ref: String,
    /// Digest of the governance-signed authorization envelope that binds the
    /// role, feed, key epoch, validity, rotation, and revocation policy.
    pub authorization_sha256: String,
    /// First venue-clock instant at which this authorization is revoked. The
    /// authorization remains audit-visible, but cannot sign or serve at or
    /// after this instant.
    pub revoked_from: Option<u64>,
}

impl FindingStatusOperatorPin {
    fn validate(&self) -> Result<PublicKey, CliError> {
        if self.feed_id.is_empty()
            || self.feed_id.len() > 512
            || !self.feed_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
            })
        {
            return Err(CliError::cli_other_error(
                "finding-market status feed id is not a portable wire identifier".to_string(),
            ));
        }
        if self.role != FINDING_STATUS_OPERATOR_ROLE {
            return Err(CliError::cli_other_error(
                "finding-market status operator role is invalid".to_string(),
            ));
        }
        if !self
            .authority
            .authority_id
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
        {
            return Err(CliError::cli_other_error(
                "finding-market status operator authority id is not a portable wire identifier"
                    .to_string(),
            ));
        }
        if self.rotation_policy_ref.trim().is_empty()
            || self.rotation_policy_ref.trim() != self.rotation_policy_ref
        {
            return Err(CliError::cli_other_error(
                "finding-market status operator rotation policy ref is invalid".to_string(),
            ));
        }
        if self.authorization_sha256.len() != 64
            || !self
                .authorization_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(CliError::cli_other_error(
                "finding-market status operator authorization digest is invalid".to_string(),
            ));
        }
        if self.revoked_from.is_some_and(|revoked_from| {
            revoked_from <= self.authority.valid_from || revoked_from > self.authority.valid_until
        }) {
            return Err(CliError::cli_other_error(
                "finding-market status operator revocation time is invalid".to_string(),
            ));
        }
        let key = self.authority.validate("status operator")?;
        FindingStatusOperatorAuthorization {
            role: FindingStatusOperatorRole::FindingStatusOperator,
            feed_id: self.feed_id.clone(),
            operator: FindingAuthorityKeyPolicy {
                authority_id: self.authority.authority_id.clone(),
                key: key.clone(),
                key_epoch: self.authority.key_epoch,
                valid_from: self.authority.valid_from,
                valid_until: self.authority.valid_until,
                rotation_policy_ref: self.rotation_policy_ref.clone(),
                revocation_status_ref: self.authority.revocation_status_ref.clone(),
            },
            revoked_from: self.revoked_from,
        }
        .validate()
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "finding-market status operator authorization is invalid: {error}"
            ))
        })?;
        Ok(key)
    }

    /// Require this exact feed and a live, non-revoked authorized operator at
    /// the venue clock. An operator rotation retains `feed_id` but changes the
    /// pinned key epoch and key through a validated configuration update.
    pub fn require_live(&self, feed_id: &str, now: u64) -> Result<PublicKey, CliError> {
        if feed_id != self.feed_id {
            return Err(CliError::cli_other_error(
                "finding-market status feed does not match the configured feed".to_string(),
            ));
        }
        let key = self.validate()?;
        if !self.authority.covers(now)
            || self
                .revoked_from
                .is_some_and(|revoked_from| now >= revoked_from)
        {
            return Err(CliError::cli_other_error(
                "finding-market status operator authorization is outside its validity window"
                    .to_string(),
            ));
        }
        Ok(key)
    }
}

/// Require the configured operator authorization and service bond to cover
/// both the issuance instant and the last instant promised by an inclusion
/// SLA. This prevents a durable outbox item from becoming undispatchable
/// before its own deadline.
pub(crate) fn require_status_feed_through(
    operator: &FindingStatusOperatorPin,
    service_bond: &FindingStatusServiceBond,
    feed_id: &str,
    now: u64,
    through: u64,
) -> Result<PublicKey, CliError> {
    if through < now {
        return Err(CliError::cli_other_error(
            "finding-market status inclusion deadline precedes issuance".to_string(),
        ));
    }
    let key = operator.require_live(feed_id, now)?;
    operator.require_live(feed_id, through)?;
    if !service_bond.covers(now) || !service_bond.covers(through) {
        return Err(CliError::cli_other_error(
            "finding-market status service bond does not cover the inclusion deadline".to_string(),
        ));
    }
    Ok(key)
}

/// Live service bond that makes missed inclusion and equivocation objective
/// slash conditions for a status-feed operator.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingStatusServiceBond {
    pub bond_id: String,
    pub feed_id: String,
    pub operator_id: String,
    pub locked_units: u64,
    pub currency: String,
    pub valid_from: u64,
    pub valid_until: u64,
    pub inclusion_sla_secs: u64,
    pub missed_inclusion_slash_units: u64,
    pub equivocation_slash_units: u64,
    /// Digest of the external live-bond observation or allocation envelope.
    pub evidence_sha256: String,
}

impl FindingStatusServiceBond {
    /// Validate the exact deployment-pinned bond against its operator
    /// authorization and objective slash conditions.
    pub fn validate(&self, operator: &FindingStatusOperatorPin) -> Result<(), CliError> {
        if self.bond_id.trim().is_empty() || self.bond_id.trim() != self.bond_id {
            return Err(CliError::cli_other_error(
                "finding-market status service bond id is invalid".to_string(),
            ));
        }
        if self.feed_id != operator.feed_id || self.operator_id != operator.authority.authority_id {
            return Err(CliError::cli_other_error(
                "finding-market status service bond is bound to another feed or operator"
                    .to_string(),
            ));
        }
        if self.currency.len() != 3 || !self.currency.bytes().all(|byte| byte.is_ascii_uppercase())
        {
            return Err(CliError::cli_other_error(
                "finding-market status service bond currency is invalid".to_string(),
            ));
        }
        if self.locked_units == 0
            || self.inclusion_sla_secs == 0
            || self.missed_inclusion_slash_units == 0
            || self.equivocation_slash_units == 0
            || self.missed_inclusion_slash_units > self.locked_units
            || self.equivocation_slash_units > self.locked_units
        {
            return Err(CliError::cli_other_error(
                "finding-market status service bond has invalid objective slash conditions"
                    .to_string(),
            ));
        }
        if self.valid_until <= self.valid_from {
            return Err(CliError::cli_other_error(
                "finding-market status service bond validity window is inverted".to_string(),
            ));
        }
        let overlap_from = self.valid_from.max(operator.authority.valid_from);
        let operator_valid_until = operator
            .revoked_from
            .unwrap_or(operator.authority.valid_until)
            .min(operator.authority.valid_until);
        let overlap_until = self.valid_until.min(operator_valid_until);
        if self.valid_until.saturating_sub(self.valid_from) <= self.inclusion_sla_secs
            || overlap_until.saturating_sub(overlap_from) <= self.inclusion_sla_secs
        {
            return Err(CliError::cli_other_error(
                "finding-market status service bond cannot cover one full inclusion SLA"
                    .to_string(),
            ));
        }
        if self.evidence_sha256.len() != 64
            || !self
                .evidence_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(CliError::cli_other_error(
                "finding-market status service bond evidence digest is invalid".to_string(),
            ));
        }
        Ok(())
    }

    /// Whether the externally evidenced service bond is live at `now`.
    #[must_use]
    pub const fn covers(&self, now: u64) -> bool {
        now >= self.valid_from && now < self.valid_until
    }

    /// Objective missed-inclusion slash amount, if a promised inclusion was
    /// absent at its signed deadline. An inclusion after the deadline still
    /// proves the SLA miss and cannot erase it.
    #[must_use]
    pub fn assess_missed_inclusion(
        &self,
        inclusion_deadline: u64,
        included_at: Option<u64>,
        observed_at: u64,
    ) -> Option<u64> {
        (observed_at > inclusion_deadline
            && included_at.is_none_or(|included| included > inclusion_deadline))
        .then_some(self.missed_inclusion_slash_units)
    }

    /// Objective equivocation slash amount when two signed roots claim one
    /// numeric map epoch but disagree on either signed epoch identity or root.
    #[must_use]
    pub fn assess_equivocation(
        &self,
        left_map_epoch: u64,
        left_epoch_id: &str,
        left_root_hash: &str,
        right_map_epoch: u64,
        right_epoch_id: &str,
        right_root_hash: &str,
    ) -> Option<u64> {
        (left_map_epoch == right_map_epoch
            && (left_epoch_id != right_epoch_id || left_root_hash != right_root_hash))
            .then_some(self.equivocation_slash_units)
    }
}

/// The finding-market deployment configuration. `None` on
/// `TrustServiceConfig` keeps every finding surface at 409, matching the
/// fiscal-runtime gating convention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingMarketConfig {
    pub venue_id: String,
    pub venue: FindingAuthorityPin,
    /// Namespace owner authorized to sign listings accepted by this
    /// venue. This is independent of the fee-schedule operator roster.
    pub listing: FindingAuthorityPin,
    pub governance_root: FindingAuthorityPin,
    /// Independently signs revocation-status readings for every market
    /// role, including the governance root. Keeping this key outside the
    /// governed roster prevents a compromised governance root from
    /// declaring itself and its delegates live.
    pub authority_status: FindingAuthorityPin,
    pub verifier_report: FindingAuthorityPin,
    pub collateral: FindingAuthorityPin,
    pub purchase: FindingAuthorityPin,
    pub failed_delivery: FindingAuthorityPin,
    /// Signs challenge outcomes. Disjoint from every other role: a key
    /// that adjudicates must not also be able to authorize the
    /// enforcement, the penalty, or the collateral reading its verdict
    /// spends against.
    pub challenge_evaluator: FindingAuthorityPin,
    /// Signs challenge enforcement instructions.
    pub venue_finalization: FindingAuthorityPin,
    /// Signs open-market penalties for the finding lane.
    pub market_penalty: FindingAuthorityPin,
    /// Signs finalized bond snapshots. The control plane only verifies
    /// against this pin; it never holds the observer's private key.
    pub settlement_observer: FindingAuthorityPin,
    /// Kernel authorized to publish the mediated enforcement-root receipt
    /// that the settlement planner accepts.
    pub anchor_publisher: FindingAuthorityPin,
    /// Oldest collateral snapshot the settlement choke point may accept.
    pub max_snapshot_age_secs: u64,
    /// Chain finality required before a finding enforcement may impair
    /// collateral. The settlement observer cannot weaken this requirement in
    /// a signed snapshot.
    pub settlement_finality_requirement: FindingFinalityRequirement,
    /// Authorizes bondless venue audits. A buyer submission verifies
    /// against its own named challenger instead.
    pub audit_authority: FindingAuthorityPin,
    /// Independently witnesses each audit seed commitment before the
    /// eligible listing snapshot is taken. This role must be disjoint from
    /// the venue and audit authority so neither can grind the seed after
    /// observing the snapshot.
    pub audit_randomness_witness: FindingAuthorityPin,
    pub audit_pool: FindingPoolPin,
    pub challenge_administration_pool: FindingPoolPin,
    pub community_fund_destination: String,
    pub status_feed_operator_ref: String,
    pub status_feed_operator: FindingStatusOperatorPin,
    pub status_feed_service_bond: FindingStatusServiceBond,
    /// Maximum age of a signed epoch and its portable proof at admission.
    pub status_max_epoch_age_secs: u64,
    /// Trusted open-market fee-schedule signer keys (canonical bare
    /// lowercase Ed25519 hex). A schedule verifies only against this
    /// pinned set; the envelope's own embedded signer never
    /// self-authorizes.
    pub fee_schedule_operator_keys: Vec<String>,
}

impl FindingMarketConfig {
    pub fn validate(&self) -> Result<(), CliError> {
        if self.venue_id.trim().is_empty() {
            return Err(CliError::cli_other_error(
                "finding-market venue id must be non-empty".to_string(),
            ));
        }
        let roster = self.roster()?;
        self.listing.validate("listing")?;
        self.settlement_finality_requirement
            .validate()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        if self.max_snapshot_age_secs == 0 {
            return Err(CliError::cli_other_error(
                "finding-market maximum snapshot age must be nonzero".to_string(),
            ));
        }
        self.audit_pool.validate("audit")?;
        self.challenge_administration_pool
            .validate("challenge administration")?;
        // The two pools are non-substitutable: distinct principals AND
        // distinct rail destinations, always.
        if self.audit_pool.principal_id == self.challenge_administration_pool.principal_id
            || self.audit_pool.rail_destination
                == self.challenge_administration_pool.rail_destination
        {
            return Err(CliError::cli_other_error(
                "finding-market audit and challenge-administration pools must be distinct"
                    .to_string(),
            ));
        }
        chio_finding::validate_evm_payout_destination(&self.community_fund_destination).map_err(
            |_| {
                CliError::cli_other_error(
                    "finding-market community fund destination must be a canonical EVM address"
                        .to_string(),
                )
            },
        )?;
        if self.status_feed_operator_ref.trim().is_empty() {
            return Err(CliError::cli_other_error(
                "finding-market status feed operator ref must be non-empty".to_string(),
            ));
        }
        if self.status_feed_operator_ref != self.status_feed_operator.feed_id {
            return Err(CliError::cli_other_error(
                "finding-market status feed reference does not match its operator authorization"
                    .to_string(),
            ));
        }
        self.status_feed_operator.validate()?;
        self.status_feed_service_bond
            .validate(&self.status_feed_operator)?;
        if self.status_max_epoch_age_secs == 0
            || self.status_max_epoch_age_secs > FINDING_STATUS_MAX_EPOCH_AGE_SECS
        {
            return Err(CliError::cli_other_error(
                "finding-market status max epoch age must be a positive I-JSON safe integer"
                    .to_string(),
            ));
        }
        if self.fee_schedule_operator_keys.is_empty() {
            return Err(CliError::cli_other_error(
                "finding-market fee schedule operator keys must be non-empty".to_string(),
            ));
        }
        let mut fee_schedule_operators = Vec::with_capacity(self.fee_schedule_operator_keys.len());
        for key_hex in &self.fee_schedule_operator_keys {
            let key = PublicKey::from_hex(key_hex).map_err(|_| {
                CliError::cli_other_error(
                    "finding-market fee schedule operator key is not valid".to_string(),
                )
            })?;
            if key.algorithm() != SigningAlgorithm::Ed25519
                || key.is_weak_ed25519()
                || key.to_hex() != *key_hex
            {
                return Err(CliError::cli_other_error(
                    "finding-market fee schedule operator key must be a canonical, non-weak Ed25519 key"
                        .to_string(),
                ));
            }
            if let Some((role, _)) = roster.iter().find(|(_, role_key)| role_key == &key) {
                return Err(CliError::cli_other_error(format!(
                    "finding-market fee schedule operator and {role} authority must be distinct keys"
                )));
            }
            if fee_schedule_operators
                .iter()
                .any(|operator| operator == &key)
            {
                return Err(CliError::cli_other_error(
                    "finding-market fee schedule operator keys must be distinct".to_string(),
                ));
            }
            fee_schedule_operators.push(key);
        }
        Ok(())
    }

    /// Validate every pinned authority and prove the roles are disjoint,
    /// returning the parsed roster in role order.
    ///
    /// Disjointness is checked here rather than at each use because one
    /// key holding two roles collapses a separation the whole lane rests
    /// on: the evaluator that decides a verdict would also be able to
    /// sign the enforcement that spends against it, and the observer that
    /// reads the collateral would be able to authorize the impairment it
    /// reported.
    pub fn roster(&self) -> Result<Vec<(&'static str, PublicKey)>, CliError> {
        let roster = [
            ("venue", &self.venue),
            ("listing", &self.listing),
            ("governance root", &self.governance_root),
            ("authority status", &self.authority_status),
            ("verifier report", &self.verifier_report),
            ("collateral", &self.collateral),
            ("purchase", &self.purchase),
            ("failed delivery", &self.failed_delivery),
            ("challenge evaluator", &self.challenge_evaluator),
            ("venue finalization", &self.venue_finalization),
            ("market penalty", &self.market_penalty),
            ("settlement observer", &self.settlement_observer),
            ("anchor publisher", &self.anchor_publisher),
            ("audit authority", &self.audit_authority),
            ("audit randomness witness", &self.audit_randomness_witness),
            ("status operator", &self.status_feed_operator.authority),
        ];
        let mut parsed = Vec::with_capacity(roster.len());
        for (label, pin) in roster {
            parsed.push((label, pin.validate(label)?));
        }
        for (index, (label, key)) in parsed.iter().enumerate() {
            if let Some((other, _)) = parsed
                .iter()
                .skip(index.saturating_add(1))
                .find(|(_, candidate)| candidate == key)
            {
                return Err(CliError::cli_other_error(format!(
                    "finding-market {label} and {other} authorities must be distinct keys"
                )));
            }
        }
        Ok(parsed)
    }

    /// The parsed pinned fee-schedule signer set.
    pub fn fee_schedule_operators(&self) -> Result<Vec<PublicKey>, CliError> {
        self.fee_schedule_operator_keys
            .iter()
            .map(|key_hex| {
                PublicKey::from_hex(key_hex).map_err(|_| {
                    CliError::cli_other_error(
                        "pinned finding-market fee schedule operator key is not valid".to_string(),
                    )
                })
            })
            .collect()
    }

    /// Require the configured status operator authorization and its service
    /// bond to be live for an exact feed at the venue clock.
    pub fn require_live_status_feed(&self, feed_id: &str, now: u64) -> Result<PublicKey, CliError> {
        require_status_feed_through(
            &self.status_feed_operator,
            &self.status_feed_service_bond,
            feed_id,
            now,
            now,
        )
    }
}

#[cfg(test)]
mod status_feed_config_tests {
    use super::*;
    use chio_core::crypto::Keypair;
    use chio_test_support::prelude::*;

    const FEED_ID: &str = "status-feed/test-venue";

    fn operator() -> FindingStatusOperatorPin {
        FindingStatusOperatorPin {
            feed_id: FEED_ID.to_string(),
            role: FINDING_STATUS_OPERATOR_ROLE.to_string(),
            authority: FindingAuthorityPin {
                authority_id: "status-operator".to_string(),
                key_hex: Keypair::from_seed(&[91; 32]).public_key().to_hex(),
                key_epoch: 7,
                valid_from: 100,
                valid_until: 500,
                revocation_status_ref: "revocations/status-operator".to_string(),
            },
            rotation_policy_ref: "rotation/status-feed-v1".to_string(),
            authorization_sha256: chio_core::sha256_hex(b"status-operator-authorization"),
            revoked_from: None,
        }
    }

    fn bond() -> FindingStatusServiceBond {
        FindingStatusServiceBond {
            bond_id: "bond-status-test".to_string(),
            feed_id: FEED_ID.to_string(),
            operator_id: "status-operator".to_string(),
            locked_units: 1_000,
            currency: "USD".to_string(),
            valid_from: 100,
            valid_until: 400,
            inclusion_sla_secs: 60,
            missed_inclusion_slash_units: 100,
            equivocation_slash_units: 1_000,
            evidence_sha256: chio_core::sha256_hex(b"status-bond"),
        }
    }

    #[test]
    fn status_operator_requires_exact_role_and_live_key_window() {
        let mut pin = operator();
        pin.role = "venue".to_string();
        assert!(pin.validate().is_err());

        let pin = operator();
        assert!(pin.require_live(FEED_ID, 100).is_ok());
        assert!(pin.require_live(FEED_ID, 499).is_ok());
        assert!(pin.require_live(FEED_ID, 500).is_err());
        assert!(pin.require_live("status-feed/other", 200).is_err());

        let mut invalid = operator();
        invalid.feed_id = "status feed/test".to_string();
        assert!(invalid.validate().is_err());
        invalid.feed_id = "status-feed/café".to_string();
        assert!(invalid.validate().is_err());

        let mut oversized_authority_id = operator();
        oversized_authority_id.authority.authority_id = "a".repeat(513);
        assert!(oversized_authority_id.validate().is_err());

        let mut nonportable_authority_id = operator();
        nonportable_authority_id.authority.authority_id = "status-opérator".to_string();
        assert!(nonportable_authority_id.validate().is_err());

        let mut oversized_rotation_ref = operator();
        oversized_rotation_ref.rotation_policy_ref = "r".repeat(513);
        assert!(oversized_rotation_ref.validate().is_err());

        let mut oversized_revocation_ref = operator();
        oversized_revocation_ref.authority.revocation_status_ref = "s".repeat(513);
        assert!(oversized_revocation_ref.validate().is_err());
    }

    #[test]
    fn revoked_operator_and_mismatched_bond_fail_closed() {
        let mut pin = operator();
        pin.revoked_from = Some(200);
        assert!(pin.require_live(FEED_ID, 200).is_err());

        let mut never_live = operator();
        never_live.revoked_from = Some(never_live.authority.valid_from);
        assert!(never_live.validate().is_err());
        never_live.revoked_from = Some(never_live.authority.valid_from - 1);
        assert!(never_live.validate().is_err());

        let pin = operator();
        let mut service_bond = bond();
        service_bond.operator_id = "substitute-operator".to_string();
        assert!(service_bond.validate(&pin).is_err());
    }

    #[test]
    fn service_bond_has_objective_live_slash_conditions() {
        let pin = operator();
        let service_bond = bond();
        service_bond
            .validate(&pin)
            .test_expect("valid status service bond");
        assert!(service_bond.covers(100));
        assert!(service_bond.covers(399));
        assert!(!service_bond.covers(400));
        assert!(require_status_feed_through(&pin, &service_bond, FEED_ID, 300, 399).is_ok());
        assert!(require_status_feed_through(&pin, &service_bond, FEED_ID, 300, 400).is_err());

        let mut missing_sla = service_bond.clone();
        missing_sla.inclusion_sla_secs = 0;
        assert!(missing_sla.validate(&pin).is_err());

        let mut short_bond = service_bond.clone();
        short_bond.valid_until = short_bond.valid_from + short_bond.inclusion_sla_secs;
        assert!(short_bond.validate(&pin).is_err());

        let mut short_operator_overlap = service_bond.clone();
        short_operator_overlap.valid_from =
            pin.authority.valid_until - short_operator_overlap.inclusion_sla_secs;
        short_operator_overlap.valid_until = pin.authority.valid_until + 100;
        assert!(short_operator_overlap.validate(&pin).is_err());

        let mut revoked_before_sla = pin.clone();
        revoked_before_sla.revoked_from = Some(
            service_bond
                .valid_from
                .saturating_add(service_bond.inclusion_sla_secs),
        );
        assert!(service_bond.validate(&revoked_before_sla).is_err());

        let mut revoked_after_sla = pin.clone();
        revoked_after_sla.revoked_from = Some(
            service_bond
                .valid_from
                .saturating_add(service_bond.inclusion_sla_secs)
                .saturating_add(1),
        );
        service_bond
            .validate(&revoked_after_sla)
            .test_expect("one full SLA fits before operator revocation");

        let mut unbacked_equivocation = service_bond;
        unbacked_equivocation.equivocation_slash_units = 1_001;
        assert!(unbacked_equivocation.validate(&pin).is_err());
    }

    #[test]
    fn status_service_bond_faults_are_mechanically_assessable() {
        let service_bond = bond();
        assert_eq!(service_bond.assess_missed_inclusion(250, None, 250), None);
        assert_eq!(
            service_bond.assess_missed_inclusion(250, None, 251),
            Some(100)
        );
        assert_eq!(
            service_bond.assess_missed_inclusion(250, Some(251), 300),
            Some(100)
        );
        assert_eq!(
            service_bond.assess_missed_inclusion(250, Some(250), 300),
            None
        );
        assert_eq!(
            service_bond.assess_equivocation(9, "epoch-a", "root-a", 9, "epoch-b", "root-a"),
            Some(1_000)
        );
        assert_eq!(
            service_bond.assess_equivocation(9, "epoch-a", "root-a", 10, "epoch-b", "root-b"),
            None
        );
    }

    #[test]
    fn selected_status_nonce_is_i_json_safe_and_fixed() {
        const {
            assert!(FINDING_STATUS_KEY_DOMAIN_NONCE < (1_u64 << 53));
        }
        assert_eq!(FINDING_STATUS_KEY_DOMAIN_NONCE, 3_318_287_169_837_494);
    }
}
