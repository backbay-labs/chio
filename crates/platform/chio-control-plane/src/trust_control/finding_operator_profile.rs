//! Strict deployment profile for the single-operator cognition market.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Component, Path};

use chio_core::crypto::Keypair;
use serde::{Deserialize, Serialize};

use super::finding_operator_purchase::{
    FindingOperatorBuyerCredential, FindingOperatorPurchaseKeys,
};
use super::FindingMarketConfig;

pub const FINDING_OPERATOR_PROFILE_SCHEMA: &str = "chio.finding.operator-profile.v1";
pub const FINDING_OPERATOR_CLIENT_PROFILE_SCHEMA: &str = "chio.finding.operator-client-profile.v1";
pub const FINDING_OPERATOR_BUYER_CLIENT_SCHEMA: &str = "chio.finding.buyer-client.v1";
pub const FINDING_OPERATOR_SELLER_CLIENT_SCHEMA: &str = "chio.finding.seller-client.v1";

/// Public trust pins and endpoint consumed by independent buyer verifiers.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingOperatorClientProfile {
    pub schema: String,
    pub endpoint: String,
    pub market: FindingMarketConfig,
}

impl FindingOperatorClientProfile {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != FINDING_OPERATOR_CLIENT_PROFILE_SCHEMA
            || !self.endpoint.starts_with("http://")
            || self.endpoint.trim_end_matches('/').len() <= "http://".len()
        {
            return Err("finding operator client profile is invalid".to_owned());
        }
        self.market.validate().map_err(|error| error.to_string())
    }
}

/// One buyer's scoped credential. It contains no operator service token or
/// operator signing role.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingOperatorBuyerClientProfile {
    pub schema: String,
    pub endpoint: String,
    pub market: FindingMarketConfig,
    pub principal_id: String,
    pub bearer_token: String,
    pub signing_seed: String,
    pub payout_destination: String,
}

/// One seller's scoped credential. Operator authority keys and the global
/// service credential are deliberately absent.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingOperatorSellerClientProfile {
    pub schema: String,
    pub endpoint: String,
    pub market: FindingMarketConfig,
    pub principal_id: String,
    pub bearer_token: String,
    pub payout_destination: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingOperatorPaths {
    pub authority_database: String,
    pub authority_lock_root: String,
    pub operator_database: String,
    pub receipt_database: String,
    pub packages_directory: String,
    pub reports_directory: String,
}

/// Private Ed25519 seeds for every disjoint market role.
///
/// This type deliberately omits `Debug` so accidental structured logging does
/// not disclose the profile's signing material.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingOperatorSecretSeeds {
    pub venue: String,
    pub listing: String,
    pub governance_root: String,
    pub authority_status: String,
    pub verifier_report: String,
    pub collateral: String,
    pub purchase: String,
    pub failed_delivery: String,
    pub challenge_evaluator: String,
    pub venue_finalization: String,
    pub market_penalty: String,
    pub settlement_observer: String,
    pub anchor_publisher: String,
    pub audit_authority: String,
    pub audit_randomness_witness: String,
    pub status_feed_operator: String,
    pub fee_schedule_operator: String,
    pub kernel: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingOperatorBuyerProfile {
    pub principal_id: String,
    pub bearer_token: String,
    pub signing_seed: String,
    pub payout_destination: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingOperatorSellerProfile {
    pub principal_id: String,
    pub bearer_token: String,
    pub signing_seed: String,
    pub payout_destination: String,
}

/// Private keys needed by the local verified-fix authoring pipeline.
///
/// This type deliberately omits `Debug` because it contains private signing
/// material. The keys stay local to the package command and are never placed
/// in the public proof bundle.
pub struct FindingOperatorAuthoringKeys {
    pub venue: Keypair,
    pub listing: Keypair,
    pub governance_root: Keypair,
    pub authority_status: Keypair,
    pub verifier_report: Keypair,
    pub collateral: Keypair,
    pub fee_schedule_operator: Keypair,
    pub production_kernel: Keypair,
    pub delivery_receipt: Keypair,
    pub replay_receipt: Keypair,
    pub checkpoint: Keypair,
    pub purchase: Keypair,
    pub failed_delivery: Keypair,
    pub status_feed_operator: Keypair,
}

/// Private roles used only by the durable challenge coordinator.
pub struct FindingOperatorChallengeKeys {
    pub evaluator: Keypair,
    pub finalization: Keypair,
    pub penalty: Keypair,
}

/// One closed profile file consumed by `operator serve`, package authoring,
/// admission, and the buyer clients.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingOperatorProfile {
    pub schema: String,
    pub listen: SocketAddr,
    pub service_token: String,
    pub paths: FindingOperatorPaths,
    pub market: FindingMarketConfig,
    pub secrets: FindingOperatorSecretSeeds,
    pub payload_key_hex: String,
    pub buyers: Vec<FindingOperatorBuyerProfile>,
    pub sellers: Vec<FindingOperatorSellerProfile>,
}

impl FindingOperatorProfile {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != FINDING_OPERATOR_PROFILE_SCHEMA {
            return Err("unsupported finding operator profile schema".to_owned());
        }
        validate_text(&self.service_token, "service token")?;
        self.market.validate().map_err(|error| error.to_string())?;
        for (path, label) in [
            (&self.paths.authority_database, "authority database"),
            (&self.paths.authority_lock_root, "authority lock root"),
            (&self.paths.operator_database, "operator database"),
            (&self.paths.receipt_database, "receipt database"),
            (&self.paths.packages_directory, "packages directory"),
            (&self.paths.reports_directory, "reports directory"),
        ] {
            validate_relative_path(path, label)?;
        }
        let databases = [
            self.paths.authority_database.as_str(),
            self.paths.operator_database.as_str(),
            self.paths.receipt_database.as_str(),
        ];
        if databases[0] == databases[1]
            || databases[0] == databases[2]
            || databases[1] == databases[2]
        {
            return Err("operator databases must use distinct files".to_owned());
        }
        validate_hex_32(&self.payload_key_hex, "payload key")?;

        let mut public_keys = BTreeSet::new();
        for (seed, expected, label) in self.role_seed_bindings()? {
            let keypair = canonical_keypair(seed, label)?;
            if keypair.public_key() != expected {
                return Err(format!("{label} seed does not match its market pin"));
            }
            if !public_keys.insert(keypair.public_key().to_hex()) {
                return Err("finding operator private roles must use distinct keys".to_owned());
            }
        }
        let kernel = canonical_keypair(&self.secrets.kernel, "kernel")?;
        if !public_keys.insert(kernel.public_key().to_hex()) {
            return Err("kernel key must be distinct from every market role".to_owned());
        }
        if self.buyers.is_empty() {
            return Err("finding operator profile requires at least one buyer".to_owned());
        }
        let mut principals = BTreeSet::new();
        let mut bearer_tokens = BTreeSet::new();
        for buyer in &self.buyers {
            validate_text(&buyer.principal_id, "buyer principal id")?;
            validate_text(&buyer.bearer_token, "buyer bearer token")?;
            if buyer.bearer_token == self.service_token {
                return Err("buyer bearer token must differ from the service token".to_owned());
            }
            if !principals.insert(buyer.principal_id.as_str())
                || !bearer_tokens.insert(buyer.bearer_token.as_str())
            {
                return Err("buyer principals and bearer tokens must be distinct".to_owned());
            }
            let buyer_key = canonical_keypair(&buyer.signing_seed, "buyer")?;
            if !public_keys.insert(buyer_key.public_key().to_hex()) {
                return Err("buyer key must be distinct from every operator role".to_owned());
            }
            chio_finding::canonical_evm_payout_destination(&buyer.payout_destination)
                .map_err(|error| error.to_string())?;
        }
        if self.sellers.len() != 1 {
            return Err("single-operator profile requires exactly one seller".to_owned());
        }
        let mut seller_principals = BTreeSet::new();
        for seller in &self.sellers {
            validate_text(&seller.principal_id, "seller principal id")?;
            validate_text(&seller.bearer_token, "seller bearer token")?;
            if seller.bearer_token == self.service_token
                || bearer_tokens.contains(seller.bearer_token.as_str())
            {
                return Err(
                    "seller bearer token must differ from service and buyer tokens".to_owned(),
                );
            }
            if !seller_principals.insert(seller.principal_id.as_str())
                || principals.contains(seller.principal_id.as_str())
                || !bearer_tokens.insert(seller.bearer_token.as_str())
            {
                return Err(
                    "buyer and seller principals and bearer tokens must be distinct".to_owned(),
                );
            }
            let seller_key = canonical_keypair(&seller.signing_seed, "seller")?;
            if seller_key.public_key() != self.market.listing.key().map_err(string_error)? {
                return Err(
                    "single-operator seller key must match the listing provider authority"
                        .to_owned(),
                );
            }
            chio_finding::canonical_evm_payout_destination(&seller.payout_destination)
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    pub fn authoring_keys(&self) -> Result<FindingOperatorAuthoringKeys, String> {
        self.validate()?;
        Ok(FindingOperatorAuthoringKeys {
            venue: canonical_keypair(&self.secrets.venue, "venue")?,
            listing: canonical_keypair(&self.secrets.listing, "listing")?,
            governance_root: canonical_keypair(&self.secrets.governance_root, "governance root")?,
            authority_status: canonical_keypair(
                &self.secrets.authority_status,
                "authority status",
            )?,
            verifier_report: canonical_keypair(&self.secrets.verifier_report, "verifier report")?,
            collateral: canonical_keypair(&self.secrets.collateral, "collateral")?,
            fee_schedule_operator: canonical_keypair(
                &self.secrets.fee_schedule_operator,
                "fee schedule operator",
            )?,
            production_kernel: canonical_keypair(&self.secrets.kernel, "kernel")?,
            delivery_receipt: canonical_keypair(&self.secrets.audit_authority, "delivery receipt")?,
            replay_receipt: canonical_keypair(
                &self.secrets.audit_randomness_witness,
                "replay receipt",
            )?,
            checkpoint: canonical_keypair(&self.secrets.anchor_publisher, "checkpoint")?,
            purchase: canonical_keypair(&self.secrets.purchase, "purchase")?,
            failed_delivery: canonical_keypair(&self.secrets.failed_delivery, "failed delivery")?,
            status_feed_operator: canonical_keypair(
                &self.secrets.status_feed_operator,
                "status feed operator",
            )?,
        })
    }

    #[must_use]
    pub fn client_profile(&self) -> FindingOperatorClientProfile {
        FindingOperatorClientProfile {
            schema: FINDING_OPERATOR_CLIENT_PROFILE_SCHEMA.to_owned(),
            endpoint: format!("http://{}", self.listen),
            market: self.market.clone(),
        }
    }

    pub fn buyer_client_profiles(&self) -> Vec<FindingOperatorBuyerClientProfile> {
        let endpoint = format!("http://{}", self.listen);
        self.buyers
            .iter()
            .map(|buyer| FindingOperatorBuyerClientProfile {
                schema: FINDING_OPERATOR_BUYER_CLIENT_SCHEMA.to_owned(),
                endpoint: endpoint.clone(),
                market: self.market.clone(),
                principal_id: buyer.principal_id.clone(),
                bearer_token: buyer.bearer_token.clone(),
                signing_seed: buyer.signing_seed.clone(),
                payout_destination: buyer.payout_destination.clone(),
            })
            .collect()
    }

    pub fn seller_client_profiles(&self) -> Vec<FindingOperatorSellerClientProfile> {
        let endpoint = format!("http://{}", self.listen);
        self.sellers
            .iter()
            .map(|seller| FindingOperatorSellerClientProfile {
                schema: FINDING_OPERATOR_SELLER_CLIENT_SCHEMA.to_owned(),
                endpoint: endpoint.clone(),
                market: self.market.clone(),
                principal_id: seller.principal_id.clone(),
                bearer_token: seller.bearer_token.clone(),
                payout_destination: seller.payout_destination.clone(),
            })
            .collect()
    }

    pub fn seller(&self, principal_id: &str) -> Result<&FindingOperatorSellerProfile, String> {
        self.sellers
            .iter()
            .find(|seller| seller.principal_id == principal_id)
            .ok_or_else(|| "seller principal is not configured".to_owned())
    }

    pub fn purchase_keys(&self) -> Result<FindingOperatorPurchaseKeys, String> {
        self.validate()?;
        let sellers = self
            .sellers
            .iter()
            .map(|seller| canonical_keypair(&seller.signing_seed, "seller"))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FindingOperatorPurchaseKeys {
            listing: canonical_keypair(&self.secrets.listing, "listing")?,
            purchase: canonical_keypair(&self.secrets.purchase, "purchase")?,
            failed_delivery: canonical_keypair(&self.secrets.failed_delivery, "failed delivery")?,
            status_operator: canonical_keypair(
                &self.secrets.status_feed_operator,
                "status feed operator",
            )?,
            kernel: canonical_keypair(&self.secrets.kernel, "kernel")?,
            sellers,
        })
    }

    pub fn challenge_keys(&self) -> Result<FindingOperatorChallengeKeys, String> {
        self.validate()?;
        Ok(FindingOperatorChallengeKeys {
            evaluator: canonical_keypair(&self.secrets.challenge_evaluator, "challenge evaluator")?,
            finalization: canonical_keypair(
                &self.secrets.venue_finalization,
                "venue finalization",
            )?,
            penalty: canonical_keypair(&self.secrets.market_penalty, "market penalty")?,
        })
    }

    pub fn buyer_credentials(&self) -> Result<Vec<FindingOperatorBuyerCredential>, String> {
        self.validate()?;
        self.buyers
            .iter()
            .map(|buyer| {
                FindingOperatorBuyerCredential::new(
                    buyer.principal_id.clone(),
                    buyer.bearer_token.clone(),
                    canonical_keypair(&buyer.signing_seed, "buyer")?,
                    buyer.payout_destination.clone(),
                )
            })
            .collect()
    }

    pub fn authority_status_key(&self) -> Result<Keypair, String> {
        canonical_keypair(&self.secrets.authority_status, "authority status")
    }

    pub fn payload_key_bytes(&self) -> Result<[u8; 32], String> {
        decode_hex_32(&self.payload_key_hex, "payload key")
    }

    fn role_seed_bindings(&self) -> Result<Vec<(&str, chio_core::PublicKey, &str)>, String> {
        Ok(vec![
            (
                &self.secrets.venue,
                self.market.venue.key().map_err(string_error)?,
                "venue",
            ),
            (
                &self.secrets.listing,
                self.market.listing.key().map_err(string_error)?,
                "listing",
            ),
            (
                &self.secrets.governance_root,
                self.market.governance_root.key().map_err(string_error)?,
                "governance root",
            ),
            (
                &self.secrets.authority_status,
                self.market.authority_status.key().map_err(string_error)?,
                "authority status",
            ),
            (
                &self.secrets.verifier_report,
                self.market.verifier_report.key().map_err(string_error)?,
                "verifier report",
            ),
            (
                &self.secrets.collateral,
                self.market.collateral.key().map_err(string_error)?,
                "collateral",
            ),
            (
                &self.secrets.purchase,
                self.market.purchase.key().map_err(string_error)?,
                "purchase",
            ),
            (
                &self.secrets.failed_delivery,
                self.market.failed_delivery.key().map_err(string_error)?,
                "failed delivery",
            ),
            (
                &self.secrets.challenge_evaluator,
                self.market
                    .challenge_evaluator
                    .key()
                    .map_err(string_error)?,
                "challenge evaluator",
            ),
            (
                &self.secrets.venue_finalization,
                self.market.venue_finalization.key().map_err(string_error)?,
                "venue finalization",
            ),
            (
                &self.secrets.market_penalty,
                self.market.market_penalty.key().map_err(string_error)?,
                "market penalty",
            ),
            (
                &self.secrets.settlement_observer,
                self.market
                    .settlement_observer
                    .key()
                    .map_err(string_error)?,
                "settlement observer",
            ),
            (
                &self.secrets.anchor_publisher,
                self.market.anchor_publisher.key().map_err(string_error)?,
                "anchor publisher",
            ),
            (
                &self.secrets.audit_authority,
                self.market.audit_authority.key().map_err(string_error)?,
                "audit authority",
            ),
            (
                &self.secrets.audit_randomness_witness,
                self.market
                    .audit_randomness_witness
                    .key()
                    .map_err(string_error)?,
                "audit randomness witness",
            ),
            (
                &self.secrets.status_feed_operator,
                self.market
                    .status_feed_operator
                    .authority
                    .key()
                    .map_err(string_error)?,
                "status feed operator",
            ),
            (
                &self.secrets.fee_schedule_operator,
                self.market
                    .fee_schedule_operators()
                    .map_err(string_error)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| "fee schedule operator pin is missing".to_owned())?,
                "fee schedule operator",
            ),
        ])
    }
}

fn canonical_keypair(seed: &str, label: &str) -> Result<Keypair, String> {
    validate_hex_32(seed, label)?;
    let keypair = Keypair::from_seed_hex(seed).map_err(|error| error.to_string())?;
    if keypair.seed_hex() != seed {
        return Err(format!("{label} seed is not canonical lowercase hex"));
    }
    Ok(keypair)
}

fn validate_hex_32(value: &str, label: &str) -> Result<(), String> {
    decode_hex_32(value, label).map(|_| ())
}

fn decode_hex_32(value: &str, label: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} must be 64 lowercase hex characters"));
    }
    let bytes = hex::decode(value).map_err(|_| format!("{label} is invalid hex"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} must decode to 32 bytes"))
}

fn validate_text(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 512
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

fn validate_relative_path(value: &str, label: &str) -> Result<(), String> {
    validate_text(value, label)?;
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("{label} must be a normalized relative path"));
    }
    Ok(())
}

fn string_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}
