//! Deployment-pinned authority roster for the cognition-market finding
//! surfaces (plan D9). Compiled only under `cognition-market-experimental`.
//!
//! Every value-moving role is pinned here, independently of whatever keys
//! artifacts embed: an envelope verifies only against its configured role,
//! and the body authority must equal that pin. Fail-closed at load: a
//! missing role, unparseable or weak key, noncanonical key encoding,
//! identical pool principals, or an inverted validity window rejects the
//! whole configuration.

use chio_core::crypto::{PublicKey, SigningAlgorithm};

use crate::CliError;

/// One pinned authority key with its lifecycle policy.
#[derive(Debug, Clone)]
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
}

/// One governance-pinned pool identity with its rail-tagged destination.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct FindingMarketConfig {
    pub venue_id: String,
    pub venue: FindingAuthorityPin,
    pub governance_root: FindingAuthorityPin,
    pub verifier_report: FindingAuthorityPin,
    pub collateral: FindingAuthorityPin,
    pub purchase: FindingAuthorityPin,
    pub failed_delivery: FindingAuthorityPin,
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
        self.venue.validate("venue")?;
        self.governance_root.validate("governance root")?;
        self.verifier_report.validate("verifier report")?;
        self.collateral.validate("collateral")?;
        self.purchase.validate("purchase")?;
        self.failed_delivery.validate("failed delivery")?;
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
        if self.community_fund_destination.trim().is_empty() {
            return Err(CliError::cli_other_error(
                "finding-market community fund destination must be non-empty".to_string(),
            ));
        }
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
