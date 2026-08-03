//! Deployment-pinned authority roster for the cognition-market finding
//! surfaces. Compiled only under `cognition-market-experimental`.
//!
//! Every value-moving role is pinned here, independently of whatever keys
//! artifacts embed: an envelope verifies only against its configured role,
//! and the body authority must equal that pin. Fail-closed at load: a
//! missing role, unparseable or weak key, noncanonical key encoding,
//! identical pool principals, or an inverted validity window rejects the
//! whole configuration.

use chio_core::crypto::{PublicKey, SigningAlgorithm};
use chio_settle::FindingFinalityRequirement;

use crate::CliError;

const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

/// One pinned authority key with its lifecycle policy.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    fn validate(&self, label: &str) -> Result<PublicKey, CliError> {
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
        self.roster()?;
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
        if self.fee_schedule_operator_keys.is_empty() {
            return Err(CliError::cli_other_error(
                "finding-market fee schedule operator keys must be non-empty".to_string(),
            ));
        }
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
            ("audit authority", &self.audit_authority),
            ("audit randomness witness", &self.audit_randomness_witness),
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
}
